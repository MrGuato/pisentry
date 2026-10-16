package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/logsrc"
)

// PortScan covers PS09. It reads kernel firewall LOG lines (UFW, firewalld
// LogDenied, or any iptables/nftables "log" rule), so it is blind unless the
// host firewall logs drops. pisentry does not sniff packets.
type PortScan struct {
	d      Deps
	mu     sync.Mutex
	hits   map[string]map[int]time.Time // src -> dport -> last seen
	protos map[string]string
	last   time.Time
}

func NewPortScan(d Deps) *PortScan {
	return &PortScan{d: d, hits: map[string]map[int]time.Time{}, protos: map[string]string{}}
}

var (
	reSRC   = regexp.MustCompile(`\bSRC=([0-9a-fA-F:.]+)`)
	reDST   = regexp.MustCompile(`\bDST=([0-9a-fA-F:.]+)`)
	reDPT   = regexp.MustCompile(`\bDPT=(\d+)`)
	rePROTO = regexp.MustCompile(`\bPROTO=(\S+)`)
)

func (p *PortScan) evictOldest() {
	var oldSrc string
	var oldT time.Time
	for s, ports := range p.hits {
		var newest time.Time
		for _, t := range ports {
			if t.After(newest) {
				newest = t
			}
		}
		if oldSrc == "" || newest.Before(oldT) {
			oldSrc, oldT = s, newest
		}
	}
	delete(p.hits, oldSrc)
	delete(p.protos, oldSrc)
}

func (p *PortScan) Handle(l logsrc.Line) {
	if !l.Kernel || !strings.Contains(l.Msg, "SRC=") {
		return
	}
	src := reSRC.FindStringSubmatch(l.Msg)
	dpt := reDPT.FindStringSubmatch(l.Msg)
	if src == nil || dpt == nil {
		return
	}
	p.d.M.FirewallDrops.Inc()
	if dst := reDST.FindStringSubmatch(l.Msg); dst != nil {
		if a, err := netip.ParseAddr(dst[1]); err == nil && (a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
			return
		}
		if strings.HasSuffix(dst[1], ".255") {
			return
		}
	}
	cfg := p.d.Cfg.PortScan
	if inPrefixes(src[1], parsePrefixes(cfg.AllowCIDRs)) {
		return
	}
	port, _ := strconv.Atoi(dpt[1])
	now := p.d.now()
	cutoff := now.Add(-cfg.Window.Duration)

	p.mu.Lock()
	m := p.hits[src[1]]
	if m == nil && len(p.hits) >= maxTrackedSources {
		p.evictOldest()
	}
	if m == nil {
		m = map[int]time.Time{}
		p.hits[src[1]] = m
	}
	for k, t := range m {
		if t.Before(cutoff) {
			delete(m, k)
		}
	}
	if len(m) < 4096 {
		m[port] = now
	}
	if pr := rePROTO.FindStringSubmatch(l.Msg); pr != nil {
		p.protos[src[1]] = pr[1]
	}
	n := len(m)
	var ports []int
	if n >= cfg.Threshold {
		for k := range m {
			ports = append(ports, k)
		}
	}
	proto := p.protos[src[1]]
	if now.Sub(p.last) > time.Minute {
		p.last = now
		for s, mm := range p.hits {
			stale := true
			for _, t := range mm {
				if !t.Before(cutoff) {
					stale = false
					break
				}
			}
			if stale {
				delete(p.hits, s)
				delete(p.protos, s)
			}
		}
	}
	p.mu.Unlock()

	if n < cfg.Threshold {
		return
	}
	sort.Ints(ports)
	sample := ports
	if len(sample) > 20 {
		sample = sample[:20]
	}
	ps := make([]string, len(sample))
	for i, v := range sample {
		ps[i] = strconv.Itoa(v)
	}
	p.d.Emit.Emit(event.Event{
		Category: event.PortScan, Severity: event.High, Detector: "portscan", Key: src[1],
		Summary: fmt.Sprintf("Port scan from %s: %d distinct ports in %s", src[1], n, event.Dur(cfg.Window.Duration)),
		Fields: map[string]string{
			"src_ip": src[1], "distinct_ports": strconv.Itoa(n), "ports": strings.Join(ps, ","),
			"proto": proto, "window": event.Dur(cfg.Window.Duration),
		},
	})
}
