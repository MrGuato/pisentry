package detect

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/procfs"
	"github.com/MrGuato/pisentry/internal/state"
)

// Ports that are almost never legitimate on a Pi and are classic backdoor or
// cleartext-auth defaults.
var backdoorPorts = map[int]string{
	23: "telnet", 1337: "backdoor", 4444: "metasploit default", 5554: "backdoor",
	6666: "irc/backdoor", 6667: "irc", 12345: "netbus", 31337: "back orifice", 54321: "backdoor",
}

// Listeners covers PS07 by diffing the host's listening sockets against a
// learned baseline. It reads /proc/1/net so it sees the host network
// namespace even when running inside a hostPID pod.
type Listeners struct {
	d        Deps
	reported map[string]bool
}

func NewListeners(d Deps) *Listeners { return &Listeners{d: d, reported: map[string]bool{}} }

func (l *Listeners) Run(ctx context.Context) {
	Loop(ctx, l.d, "listeners", l.d.Cfg.Listeners.Interval.Duration, l.Scan)
}

type listenKey struct {
	key   string
	sock  procfs.Socket
	class string
}

// classify returns "any", "loopback" or the literal bind address.
func classify(s procfs.Socket) string {
	a := s.Local.Addr()
	switch {
	case a.IsUnspecified():
		return "any"
	case a.IsLoopback():
		return "loopback"
	}
	return a.String()
}

// CurrentListeners returns the filtered listener set keyed by proto/class/port.
func (l *Listeners) CurrentListeners() (map[string]listenKey, error) {
	cfg := l.d.Cfg
	socks, err := procfs.ReadNet(cfg.ProcRoot, "1")
	if err != nil {
		socks, err = procfs.ReadNet(cfg.ProcRoot, "")
		if err != nil {
			return nil, err
		}
	}
	out := map[string]listenKey{}
	for _, s := range socks {
		if !s.IsListener() {
			continue
		}
		port := int(s.Local.Port())
		proto := strings.TrimSuffix(s.Proto, "6")
		// Unconnected UDP sockets in the ephemeral range are DNS lookups and
		// similar client traffic, not services.
		if proto == "udp" && port >= 32768 {
			continue
		}
		class := classify(s)
		if class == "loopback" && cfg.Listeners.IgnoreLoopback {
			continue
		}
		if containsInt(cfg.Listeners.AllowPorts, port) {
			continue
		}
		k := fmt.Sprintf("%s/%s/%d", proto, class, port)
		if _, dup := out[k]; !dup {
			out[k] = listenKey{key: k, sock: s, class: class}
		}
	}
	return out, nil
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (l *Listeners) Scan() error {
	cur, err := l.CurrentListeners()
	if err != nil {
		return err
	}
	now := l.d.now()
	var (
		base  map[string]state.Listener
		since time.Time
	)
	l.d.Store.View(func(s *state.State) {
		since = s.Baselines.ListenersSince
		base = make(map[string]state.Listener, len(s.Baselines.Listeners))
		for k, v := range s.Baselines.Listeners {
			base[k] = v
		}
	})
	if since.IsZero() || now.Sub(since) < l.d.Cfg.LearningPeriod.Duration {
		// Learning: everything we see is expected.
		owners := l.owners(cur, base)
		l.d.Store.Update(func(s *state.State) {
			if s.Baselines.ListenersSince.IsZero() {
				s.Baselines.ListenersSince = now.UTC()
			}
			for k, v := range cur {
				if _, ok := s.Baselines.Listeners[k]; !ok {
					s.Baselines.Listeners[k] = state.Listener{
						Proto: strings.TrimSuffix(v.sock.Proto, "6"), Addr: v.class,
						Port: int(v.sock.Local.Port()), Process: owners[k], FirstSeen: now.UTC(),
					}
				}
			}
		})
		l.d.M.UnexpectedListen.Set(0)
		l.d.M.BaselineFiles.Set(float64(len(base)+len(cur)), "listeners")
		return nil
	}

	var unexpected []string
	for k := range cur {
		if _, ok := base[k]; !ok {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(unexpected)
	l.d.M.UnexpectedListen.Set(float64(len(unexpected)))
	l.d.M.BaselineFiles.Set(float64(len(base)), "listeners")
	for k := range l.reported {
		if _, still := cur[k]; !still {
			delete(l.reported, k)
		}
	}
	var fresh []string
	for _, k := range unexpected {
		if !l.reported[k] {
			fresh = append(fresh, k)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	want := map[uint64]bool{}
	for _, k := range fresh {
		want[cur[k].sock.Inode] = true
	}
	owners := procfs.InodeOwners(l.d.Cfg.ProcRoot, want)
	for _, k := range fresh {
		lk := cur[k]
		port := int(lk.sock.Local.Port())
		sev := event.Medium
		switch lk.class {
		case "any":
			sev = event.High
		case "loopback":
			sev = event.Low
		}
		fields := map[string]string{
			"proto": lk.sock.Proto, "bind": lk.sock.Local.Addr().String(), "port": strconv.Itoa(port),
		}
		if why, bad := backdoorPorts[port]; bad && lk.class != "loopback" {
			sev = event.Critical
			fields["port_note"] = why
		}
		if o, ok := owners[lk.sock.Inode]; ok {
			fields["pid"], fields["comm"], fields["exe"] = strconv.Itoa(o.PID), o.Comm, o.Exe
		}
		who := fields["comm"]
		if who == "" {
			who = "unknown process"
		}
		l.d.Emit.Emit(event.Event{
			Category: event.NewListener, Severity: sev, Detector: "listeners", Key: k,
			Summary: fmt.Sprintf("New %s listener on %s:%d (%s), not in baseline", strings.TrimSuffix(lk.sock.Proto, "6"), lk.sock.Local.Addr(), port, who),
			Fields:  fields,
		})
		l.reported[k] = true
	}
	return nil
}

func (l *Listeners) owners(cur map[string]listenKey, base map[string]state.Listener) map[string]string {
	want := map[uint64]bool{}
	for k, v := range cur {
		if _, ok := base[k]; !ok {
			want[v.sock.Inode] = true
		}
	}
	o := procfs.InodeOwners(l.d.Cfg.ProcRoot, want)
	out := map[string]string{}
	for k, v := range cur {
		if ow, ok := o[v.sock.Inode]; ok {
			out[k] = ow.Comm
		}
	}
	return out
}
