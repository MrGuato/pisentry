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
	"github.com/MrGuato/pisentry/internal/rules"
)

// clkTck is USER_HZ, 100 on every Linux arm, arm64 and amd64 build.
const clkTck = 100

var tempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/"}

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
	rs := p.d.rules()
	eager := rs.UsesField(rules.SourceProcess, "process.uid") || rs.UsesField(rules.SourceProcess, "process.parent_comm")
	shells := cfg.Proc.ShellNames
	if len(shells) == 0 {
		shells = rs.Catalog().ShellNames
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

		// Process rules: PS06 miner names and pool command lines ship in the
		// defaults, other categories come from rule packs and rules.d.
		// proc.miner_names in the config is still honoured as an extra list.
		minerHit := false
		for _, hit := range p.matchProcessRules(rs, eager, pid, st, exe, cmd) {
			if hit.Category == event.Cryptominer {
				p.emitMiner(id, hit.Level, pid, st, exe, cmd, cpu, hit.Title, &hit)
				minerHit = true
			} else {
				p.emitRule(id, pid, st, exe, cmd, hit)
			}
		}
		if !minerHit {
			if name := matchesAny(comm+" "+filepath.Base(exe), cfg.Proc.MinerNames); name != "" {
				p.emitMiner(id, event.Critical, pid, st, exe, cmd, cpu, "known miner name: "+name, nil)
			}
		}

		if cpu >= cfg.Proc.CPUThreshold {
			s.hot++
		} else {
			s.hot = 0
		}
		if s.hot >= 2 && !contains(cfg.Proc.AllowComm, comm) {
			if why := suspiciousExe(exe); why != "" {
				p.emitMiner(id, event.Critical, pid, st, exe, cmd, cpu, "sustained high CPU, "+why, nil)
			} else if port, remote := p.stratumConn(nc, pid); port != 0 {
				p.emitMiner(id, event.High, pid, st, exe, cmd, cpu, fmt.Sprintf("sustained high CPU with connection to %s (common pool port %d)", remote, port), nil)
			} else if s.hot == cfg.Proc.SustainedPolls {
				p.emitMiner(id+"|sustained", event.Low, pid, st, exe, cmd, cpu,
					fmt.Sprintf("sustained high CPU for %d polls", s.hot), nil)
			}
		}

		// PS08: shell or interpreter whose stdin/stdout is a TCP socket.
		if isShell(comm, exe, shells) {
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

// matchProcessRules evaluates the process rules for one process and returns
// every hit. The parent comm and uid cost extra /proc reads. When no rule
// matches on them (eager false) they are only filled in, and the rules
// re-evaluated, once something has matched, which is enough for exceptions.
func (p *ProcWatch) matchProcessRules(rs *rules.Engine, eager bool, pid int, st procfs.Proc, exe, cmd string) []rules.Rule {
	in := &rules.EvalInput{
		Source:  rules.SourceProcess,
		Process: event.ProcessEntity{PID: pid, PPID: st.PPID, Comm: st.Comm, Exe: exe, Cmdline: cmd},
	}
	if !eager && len(rs.Eval(in)) == 0 {
		return nil
	}
	if uid := procfs.UID(p.d.Cfg.ProcRoot, pid); uid >= 0 {
		in.Process.UID = event.IntPtr(uid)
	}
	in.ParentComm = parentComm(p.d.Cfg.ProcRoot, st.PPID)
	return rs.Eval(in)
}

func (p *ProcWatch) stratumConn(nc *netCache, pid int) (int, string) {
	ports := p.d.Cfg.Proc.StratumPorts
	if len(ports) == 0 {
		ports = p.d.rules().Catalog().StratumPorts
	}
	for _, ino := range procfs.SocketInodes(p.d.Cfg.ProcRoot, pid) {
		s, ok := nc.lookup(pid, ino)
		if !ok || s.State != procfs.TCPEstablished {
			continue
		}
		if port := int(s.Remote.Port()); containsInt(ports, port) && !s.Remote.Addr().IsLoopback() {
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
		uid := procfs.UID(p.d.Cfg.ProcRoot, pid)
		var uidPtr *int
		var ue *event.UserEntity
		if uid >= 0 {
			uidPtr = event.IntPtr(uid)
			ue = &event.UserEntity{UID: uidPtr}
		}
		truncCmd := engine.Truncate(cmd, 300)
		p.d.emit(event.Event{
			Category: event.ReverseShell, Severity: event.Critical, Detector: "proc", Key: id,
			Summary: fmt.Sprintf("Reverse shell: %s (pid %d) has fd %d connected to %s", st.Comm, pid, fd, s.Remote),
			Process: &event.ProcessEntity{
				PID: pid, PPID: st.PPID, StartTime: st.StartTime, UID: uidPtr,
				Comm: st.Comm, Exe: exe, Cmdline: truncCmd,
			},
			Source: &event.SourceEntity{IP: s.Remote.Addr().String(), Port: int(s.Remote.Port())},
			User:   ue,
			Fields: map[string]string{
				"pid": strconv.Itoa(pid), "ppid": strconv.Itoa(st.PPID), "comm": st.Comm, "exe": exe,
				"cmdline": truncCmd, "remote": s.Remote.String(), "local": s.Local.String(),
				"fd": strconv.Itoa(fd), "uid": strconv.Itoa(uid),
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

func (p *ProcWatch) emitMiner(id string, sev event.Severity, pid int, st procfs.Proc, exe, cmd string, cpu float64, why string, hit *rules.Rule) {
	if p.flagged["miner|"+id] {
		return
	}
	p.flagged["miner|"+id] = true
	uid := procfs.UID(p.d.Cfg.ProcRoot, pid)
	var uidPtr *int
	var ue *event.UserEntity
	if uid >= 0 {
		uidPtr = event.IntPtr(uid)
		ue = &event.UserEntity{UID: uidPtr}
	}
	truncCmd := engine.Truncate(cmd, 300)
	ev := event.Event{
		Category: event.Cryptominer, Severity: sev, Detector: "proc", Key: id,
		Summary: fmt.Sprintf("Possible cryptominer %s (pid %d): %s", st.Comm, pid, why),
		Process: &event.ProcessEntity{
			PID: pid, PPID: st.PPID, StartTime: st.StartTime, UID: uidPtr,
			Comm: st.Comm, Exe: exe, Cmdline: truncCmd,
		},
		User: ue,
		Fields: map[string]string{
			"pid": strconv.Itoa(pid), "comm": st.Comm, "exe": exe, "cmdline": truncCmd,
			"cpu_percent": strconv.FormatFloat(cpu, 'f', 0, 64), "reason": why,
			"uid": strconv.Itoa(uid),
		},
	}
	if hit != nil {
		ev.MITRE = hit.MITRE
		ev.Rule = &event.RuleEntity{ID: hit.ID, Title: hit.Title}
	}
	p.d.emit(ev)
}

// emitRule reports a process rule hit outside PS06, such as a GTFOBins or
// reverse shell rule from a rule pack. Each rule fires once per process.
func (p *ProcWatch) emitRule(id string, pid int, st procfs.Proc, exe, cmd string, hit rules.Rule) {
	key := "rule|" + hit.ID + "|" + id
	if p.flagged[key] {
		return
	}
	p.flagged[key] = true
	uid := procfs.UID(p.d.Cfg.ProcRoot, pid)
	var uidPtr *int
	var ue *event.UserEntity
	if uid >= 0 {
		uidPtr = event.IntPtr(uid)
		ue = &event.UserEntity{UID: uidPtr}
	}
	truncCmd := engine.Truncate(cmd, 300)
	p.d.emit(event.Event{
		Category: hit.Category, Severity: hit.Level, Detector: "proc", Key: hit.ID + "|" + id,
		Summary: fmt.Sprintf("%s: %s (pid %d)", hit.Title, st.Comm, pid),
		MITRE:   hit.MITRE,
		Rule:    &event.RuleEntity{ID: hit.ID, Title: hit.Title},
		Process: &event.ProcessEntity{
			PID: pid, PPID: st.PPID, StartTime: st.StartTime, UID: uidPtr,
			Comm: st.Comm, Exe: exe, Cmdline: truncCmd,
		},
		User: ue,
		Fields: map[string]string{
			"pid": strconv.Itoa(pid), "comm": st.Comm, "exe": exe, "cmdline": truncCmd,
			"uid": strconv.Itoa(uid), "rule": hit.ID,
		},
	})
}
