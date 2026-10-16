package detect

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MrGuato/pisentry/internal/engine"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/procfs"
)

// clkTck is USER_HZ, 100 on every Linux arm, arm64 and amd64 build.
const clkTck = 100

var tempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/"}

var stratumMarkers = []string{"stratum+tcp://", "stratum+ssl://", "stratum+tls://", "stratum2+tcp://", "--donate-level", "--randomx", "-a rx/0", "--algo=rx", "--coin=monero", "--cpu-max-threads-hint"}

// ProcWatch covers PS06 (cryptominers) and PS08 (reverse shells) by polling
// /proc. Polling means a process that lives for less than one interval can be
// missed; that is the price of not needing eBPF or kernel modules.
type ProcWatch struct {
	d       Deps
	prev    map[int]*procSample
	last    time.Time
	flagged map[string]bool
}

type procSample struct {
	start uint64
	ticks uint64
	hot   int
	seen  bool
}

func NewProcWatch(d Deps) *ProcWatch {
	return &ProcWatch{d: d, prev: map[int]*procSample{}, flagged: map[string]bool{}}
}

func (p *ProcWatch) Run(ctx context.Context) {
	Loop(ctx, p.d, "proc", p.d.Cfg.Proc.Interval.Duration, p.Scan)
}

type netCache struct {
	proc string
	byNS map[string]map[uint64]procfs.Socket
}

func (n *netCache) lookup(pid int, ino uint64) (procfs.Socket, bool) {
	ns := procfs.NetNS(n.proc, pid)
	tbl, ok := n.byNS[ns]
	if !ok {
		tbl = map[uint64]procfs.Socket{}
		socks, _ := procfs.ReadNet(n.proc, strconv.Itoa(pid))
		for _, s := range socks {
			tbl[s.Inode] = s
		}
		n.byNS[ns] = tbl
	}
	s, ok := tbl[ino]
	return s, ok
}

func matchesAny(s string, names []string) string {
	s = strings.ToLower(s)
	for _, n := range names {
		if n != "" && strings.Contains(s, n) {
			return n
		}
	}
	return ""
}

func isShell(comm, exe string, shells []string) bool {
	base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	for _, s := range shells {
		if comm == s || base == s {
			return true
		}
		// python3.11, perl5.36, etc.
		if (s == "python" || s == "perl" || s == "ruby" || s == "php" || s == "lua") &&
			(strings.HasPrefix(comm, s) || strings.HasPrefix(base, s)) {
			return true
		}
	}
	return false
}

func suspiciousExe(exe string) string {
	if strings.HasSuffix(exe, " (deleted)") {
		return "binary deleted from disk after start"
	}
	for _, d := range tempDirs {
		if strings.HasPrefix(exe, d) {
			return "running from " + strings.TrimSuffix(d, "/")
		}
	}
	if strings.HasPrefix(filepath.Base(exe), ".") {
		return "hidden binary name"
	}
	return ""
}

func (p *ProcWatch) Scan() error {
	cfg := p.d.Cfg
	now := time.Now()
	dt := now.Sub(p.last).Seconds()
	first := p.last.IsZero()
	p.last = now
	pids, err := procfs.ListPIDs(cfg.ProcRoot)
	if err != nil {
		return err
	}
	nc := &netCache{proc: cfg.ProcRoot, byNS: map[string]map[uint64]procfs.Socket{}}
	for _, s := range p.prev {
		s.seen = false
	}
	for _, pid := range pids {
		st, err := procfs.ReadStat(cfg.ProcRoot, pid)
		if err != nil {
			continue
		}
		exe := procfs.Exe(cfg.ProcRoot, pid)
		if exe == "" {
			continue // kernel thread or exited
		}
		ticks := st.UTime + st.STime
		s := p.prev[pid]
		if s == nil || s.start != st.StartTime {
			s = &procSample{start: st.StartTime, ticks: ticks}
			p.prev[pid] = s
		}
		s.seen = true
		cpu := 0.0
		if !first && dt > 0 && ticks >= s.ticks {
			cpu = float64(ticks-s.ticks) / clkTck / dt * 100
		}
		s.ticks = ticks
		id := fmt.Sprintf("%d:%d", pid, st.StartTime)
		comm := st.Comm
		cmd := procfs.Cmdline(cfg.ProcRoot, pid)

		// PS06: known miner names and pool command lines.
		if hit := matchesAny(comm+" "+filepath.Base(exe), cfg.Proc.MinerNames); hit != "" {
			p.emitMiner(id, event.Critical, pid, st, exe, cmd, cpu, "known miner name: "+hit)
		} else if hit := matchesAny(cmd, stratumMarkers); hit != "" {
			p.emitMiner(id, event.Critical, pid, st, exe, cmd, cpu, "mining pool arguments: "+hit)
		}

		if cpu >= cfg.Proc.CPUThreshold {
			s.hot++
		} else {
			s.hot = 0
		}
		if s.hot >= 2 && !contains(cfg.Proc.AllowComm, comm) {
			if why := suspiciousExe(exe); why != "" {
				p.emitMiner(id, event.Critical, pid, st, exe, cmd, cpu, "sustained high CPU, "+why)
			} else if port, remote := p.stratumConn(nc, pid); port != 0 {
				p.emitMiner(id, event.High, pid, st, exe, cmd, cpu, fmt.Sprintf("sustained high CPU with connection to %s (common pool port %d)", remote, port))
			} else if s.hot == cfg.Proc.SustainedPolls {
				p.emitMiner(id+"|sustained", event.Low, pid, st, exe, cmd, cpu,
					fmt.Sprintf("sustained high CPU for %d polls", s.hot))
			}
		}

		// PS08: shell or interpreter whose stdin/stdout is a TCP socket.
		if isShell(comm, exe, cfg.Proc.ShellNames) {
			p.checkRevShell(nc, id, pid, st, exe, cmd)
		}
	}
	for pid, s := range p.prev {
		if !s.seen {
			delete(p.prev, pid)
		}
	}
	if len(p.flagged) > 2000 {
		p.flagged = map[string]bool{}
	}
	return nil
}

func (p *ProcWatch) stratumConn(nc *netCache, pid int) (int, string) {
	for _, ino := range procfs.SocketInodes(p.d.Cfg.ProcRoot, pid) {
		s, ok := nc.lookup(pid, ino)
		if !ok || s.State != procfs.TCPEstablished {
			continue
		}
		if port := int(s.Remote.Port()); containsInt(p.d.Cfg.Proc.StratumPorts, port) && !s.Remote.Addr().IsLoopback() {
			return port, s.Remote.String()
		}
	}
	return 0, ""
}

func (p *ProcWatch) checkRevShell(nc *netCache, id string, pid int, st procfs.Proc, exe, cmd string) {
	for fd := 0; fd <= 2; fd++ {
		ino := procfs.SocketInode(p.d.Cfg.ProcRoot, pid, fd)
		if ino == 0 {
			continue
		}
		s, ok := nc.lookup(pid, ino)
		if !ok || !strings.HasPrefix(s.Proto, "tcp") || s.State != procfs.TCPEstablished {
			continue
		}
		if p.d.Cfg.Proc.RevShellIgnoreLoopback && s.Remote.Addr().IsLoopback() {
			continue
		}
		if p.flagged["rev|"+id] {
			return
		}
		p.flagged["rev|"+id] = true
		p.d.Emit.Emit(event.Event{
			Category: event.ReverseShell, Severity: event.Critical, Detector: "proc", Key: id,
			Summary: fmt.Sprintf("Reverse shell: %s (pid %d) has fd %d connected to %s", st.Comm, pid, fd, s.Remote),
			Fields: map[string]string{
				"pid": strconv.Itoa(pid), "ppid": strconv.Itoa(st.PPID), "comm": st.Comm, "exe": exe,
				"cmdline": engine.Truncate(cmd, 300), "remote": s.Remote.String(), "local": s.Local.String(),
				"fd": strconv.Itoa(fd), "uid": strconv.Itoa(procfs.UID(p.d.Cfg.ProcRoot, pid)),
				"parent": parentComm(p.d.Cfg.ProcRoot, st.PPID),
			},
		})
		return
	}
}

func parentComm(procRoot string, ppid int) string {
	st, err := procfs.ReadStat(procRoot, ppid)
	if err != nil {
		return ""
	}
	return st.Comm
}

func (p *ProcWatch) emitMiner(id string, sev event.Severity, pid int, st procfs.Proc, exe, cmd string, cpu float64, why string) {
	if p.flagged["miner|"+id] {
		return
	}
	p.flagged["miner|"+id] = true
	p.d.Emit.Emit(event.Event{
		Category: event.Cryptominer, Severity: sev, Detector: "proc", Key: id,
		Summary: fmt.Sprintf("Possible cryptominer %s (pid %d): %s", st.Comm, pid, why),
		Fields: map[string]string{
			"pid": strconv.Itoa(pid), "comm": st.Comm, "exe": exe, "cmdline": engine.Truncate(cmd, 300),
			"cpu_percent": strconv.FormatFloat(cpu, 'f', 0, 64), "reason": why,
			"uid": strconv.Itoa(procfs.UID(p.d.Cfg.ProcRoot, pid)),
		},
	})
}
