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

	"github.com/MrGuato/pisentry/internal/engine"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/logsrc"
	"github.com/MrGuato/pisentry/internal/state"
)

// Auth covers PS01 (SSH brute force), PS02 (suspicious login) and the
// sudo/su half of PS04 (privilege escalation) from auth logs.
type Auth struct {
	d Deps

	mu          sync.Mutex
	fails       map[string][]time.Time     // ip -> failure times
	users       map[string]map[string]bool // ip -> attempted users
	invalidSeen map[string]time.Time       // ip:port already counted via "Invalid user"
	lastPrune   time.Time
}

func NewAuth(d Deps) *Auth {
	return &Auth{d: d, fails: map[string][]time.Time{}, users: map[string]map[string]bool{}, invalidSeen: map[string]time.Time{}}
}

var (
	// Usernames are attacker-controlled and may contain " from 1.2.3.4 port 1".
	// Every pattern is greedy on the username and anchored at the end so the
	// real source address (the LAST "from X port N") is always the one used.
	reFailed     = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?\s*$`)
	reInvalid    = regexp.MustCompile(`^Invalid user (.*) from (\S+) port (\d+)\s*$`)
	reClosedAuth = regexp.MustCompile(`^(?:Connection closed|Disconnected) by authenticating user (.*) (\S+) port (\d+) \[preauth\]\s*$`)
	reMaxAuth    = regexp.MustCompile(`maximum authentication attempts exceeded for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?(?: \[preauth\])?\s*$`)
	reAccepted   = regexp.MustCompile(`^Accepted (\S+) for (.*) from (\S+) port (\d+)(?: ssh2)?(?:: .*)?$`)

	reSudoNotIn     = regexp.MustCompile(`^\s*(\S+) : (?:user NOT in sudoers|user NOT authorized on host)`)
	reSudoIncorrect = regexp.MustCompile(`^\s*(\S+) : (\d+) incorrect password attempts?`)
	reSudoCmd       = regexp.MustCompile(`^\s*(\S+) : .*?USER=(\S+) ; COMMAND=(.*)$`)
	reSuFailed      = regexp.MustCompile(`FAILED SU \(to (\S+)\) (\S+) on|FAILED su for (\S+) by (\S+)|pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(\S*)`)

	// Commands run through sudo that are classic escalation or persistence moves.
	riskySudo = []*regexp.Regexp{
		regexp.MustCompile(`chmod\s+(?:[ugoa]*\+[rwx]*s|[0-7]?[2467][0-7]{3}\b)`),
		regexp.MustCompile(`/dev/tcp/|\bnc(?:at)?\s+.*-e\s|\bsocat\b.*exec:`),
		regexp.MustCompile(`\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b`),
		regexp.MustCompile(`base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba|da)?sh\b`),
		regexp.MustCompile(`\busermod\s+.*-a?G\s*(?:sudo|wheel|docker|admin)\b`),
		regexp.MustCompile(`\b(?:useradd|adduser)\b.*(?:-o\b|-u\s*0\b)`),
		regexp.MustCompile(`/etc/(?:sudoers|shadow|passwd|ld\.so\.preload)`),
		regexp.MustCompile(`\bsetcap\b`),
	}
)

// Handle processes one log line.
func (a *Auth) Handle(l logsrc.Line) {
	switch {
	case strings.HasPrefix(l.Ident, "sshd"):
		if a.d.Cfg.Logs.SSHRequireRoot && l.UID > 0 {
			a.d.M.DetectorErrors.Inc("auth_forged_sshd")
			return
		}
		a.handleSSH(l)
	case l.Ident == "sudo":
		a.handleSudo(l)
	case l.Ident == "su":
		a.handleSu(l)
	}
}

func (a *Auth) handleSSH(l logsrc.Line) {
	msg := l.Msg
	now := a.d.now()
	if m := reAccepted.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[4])
		a.success(now, m[1], m[2], m[3], port)
		return
	}
	if m := reInvalid.FindStringSubmatch(msg); m != nil {
		a.mu.Lock()
		if m[3] != "" {
			a.invalidSeen[m[2]+":"+m[3]] = now
		}
		a.mu.Unlock()
		port, _ := strconv.Atoi(m[3])
		a.fail(now, m[2], port, m[1], true)
		return
	}
	if m := reFailed.FindStringSubmatch(msg); m != nil {
		if m[2] != "" {
			a.mu.Lock()
			_, counted := a.invalidSeen[m[4]+":"+m[5]]
			delete(a.invalidSeen, m[4]+":"+m[5])
			a.mu.Unlock()
			if counted {
				return
			}
		}
		port, _ := strconv.Atoi(m[5])
		a.fail(now, m[4], port, m[3], m[2] != "")
		return
	}
	if m := reClosedAuth.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[3])
		a.fail(now, m[2], port, m[1], false)
		return
	}
	if m := reMaxAuth.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[4])
		a.fail(now, m[3], port, m[2], m[1] != "")
	}
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

func countSince(ts []time.Time, cutoff time.Time) int {
	n := 0
	for _, t := range ts {
		if !t.Before(cutoff) {
			n++
		}
	}
	return n
}

func validIP(ip string) bool {
	_, err := netip.ParseAddr(ip)
	return err == nil
}

func (a *Auth) fail(now time.Time, ip string, port int, user string, invalid bool) {
	a.d.M.SSHFailures.Inc()
	if !validIP(ip) {
		return
	}
	cfg := a.d.Cfg.SSH
	if inPrefixes(ip, parsePrefixes(cfg.AllowCIDRs)) {
		return
	}
	keep := cfg.FailWindow.Duration
	if cfg.SuccessAfterFailWindow.Duration > keep {
		keep = cfg.SuccessAfterFailWindow.Duration
	}
	a.mu.Lock()
	a.fails[ip] = append(prune(a.fails[ip], now.Add(-keep)), now)
	if len(a.fails[ip]) > 1000 { // cap per-source history
		a.fails[ip] = a.fails[ip][len(a.fails[ip])-1000:]
	}
	if len(a.fails) > maxTrackedSources {
		a.evictOldest()
	}
	if a.users[ip] == nil {
		a.users[ip] = map[string]bool{}
	}
	if len(a.users[ip]) < 50 {
		a.users[ip][user] = true
	}
	n := countSince(a.fails[ip], now.Add(-cfg.FailWindow.Duration))
	users := sortedKeys(a.users[ip], 8)
	a.maybePrune(now, keep)
	a.mu.Unlock()

	var sev event.Severity
	key := ip
	switch {
	case n >= cfg.FailThreshold*4:
		sev, key = event.Critical, ip+"|sustained"
	case n >= cfg.FailThreshold:
		sev = event.High
	default:
		return
	}
	a.d.emit(event.Event{
		Category: event.SSHBruteForce, Severity: sev, Detector: "auth", Key: key,
		Summary: fmt.Sprintf("SSH brute force from %s: %d failed attempts in %s", ip, n, event.Dur(cfg.FailWindow.Duration)),
		Source:  &event.SourceEntity{IP: ip, Port: port},
		User:    userEntity(engine.Truncate(user, 64)),
		Fields: map[string]string{
			"src_ip": ip, "failures": strconv.Itoa(n), "window": event.Dur(cfg.FailWindow.Duration),
			"users": engine.Truncate(strings.Join(users, ","), 200),
		},
	})
}

func (a *Auth) maybePrune(now time.Time, keep time.Duration) {
	if now.Sub(a.lastPrune) < time.Minute {
		return
	}
	a.lastPrune = now
	for ip, ts := range a.fails {
		if ts = prune(ts, now.Add(-keep)); len(ts) == 0 {
			delete(a.fails, ip)
			delete(a.users, ip)
		} else {
			a.fails[ip] = ts
		}
	}
	for k, t := range a.invalidSeen {
		if now.Sub(t) > 10*time.Minute {
			delete(a.invalidSeen, k)
		}
	}
}

// maxTrackedSources bounds memory when an attacker sprays many source IPs.
const maxTrackedSources = 10000

func (a *Auth) evictOldest() {
	var oldIP string
	var oldT time.Time
	for ip, ts := range a.fails {
		if len(ts) == 0 {
			oldIP = ip
			break
		}
		if t := ts[len(ts)-1]; oldIP == "" || t.Before(oldT) {
			oldIP, oldT = ip, t
		}
	}
	delete(a.fails, oldIP)
	delete(a.users, oldIP)
}

func sortedKeys(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func (a *Auth) success(now time.Time, method, user, ip string, port int) {
	cfg := a.d.Cfg.SSH
	if !validIP(ip) {
		return
	}
	a.mu.Lock()
	recent := countSince(a.fails[ip], now.Add(-cfg.SuccessAfterFailWindow.Duration))
	a.mu.Unlock()

	learning := a.d.learning()
	known := false
	a.d.Store.Update(func(s *state.State) {
		if s.Baselines.Logins[user] == nil {
			s.Baselines.Logins[user] = map[string]time.Time{}
		}
		_, known = s.Baselines.Logins[user][ip]
		if len(s.Baselines.Logins[user]) < 500 {
			s.Baselines.Logins[user][ip] = now.UTC()
		}
	})

	sev := event.Info
	var reasons []string
	if recent >= cfg.SuccessAfterFailMin {
		sev = event.Critical
		reasons = append(reasons, fmt.Sprintf("after %d failed attempts from the same source", recent))
	}
	if user == "root" {
		sev = maxSev(sev, event.High)
		reasons = append(reasons, "direct root login")
	}
	if !known && !learning && !inPrefixes(ip, parsePrefixes(cfg.AllowCIDRs)) {
		sev = maxSev(sev, event.Medium)
		reasons = append(reasons, "first login for this user from this source")
	}
	if sev == event.Info {
		return
	}
	a.d.emit(event.Event{
		Category: event.SuspiciousLogin, Severity: sev, Detector: "auth", Key: user + "|" + ip,
		Summary: fmt.Sprintf("SSH login as %s from %s (%s): %s", user, ip, method, strings.Join(reasons, "; ")),
		Source:  &event.SourceEntity{IP: ip, Port: port},
		User:    userEntity(engine.Truncate(user, 64)),
		Fields: map[string]string{
			"user": engine.Truncate(user, 64), "src_ip": ip, "method": method,
			"recent_failures": strconv.Itoa(recent),
		},
	})
}

func (a *Auth) handleSudo(l logsrc.Line) {
	msg := l.Msg
	if m := reSudoNotIn.FindStringSubmatch(msg); m != nil {
		a.d.emit(event.Event{
			Category: event.PrivEsc, Severity: event.High, Detector: "auth", Key: "sudo-denied|" + m[1],
			Summary: fmt.Sprintf("User %s tried sudo but is not in sudoers", m[1]),
			User:    userEntity(m[1]),
			Fields:  map[string]string{"user": m[1], "log": engine.Truncate(msg, 300)},
		})
		return
	}
	if m := reSudoIncorrect.FindStringSubmatch(msg); m != nil {
		a.d.emit(event.Event{
			Category: event.PrivEsc, Severity: event.Medium, Detector: "auth", Key: "sudo-badpw|" + m[1],
			Summary: fmt.Sprintf("User %s failed the sudo password %s times", m[1], m[2]),
			User:    userEntity(m[1]),
			Fields:  map[string]string{"user": m[1], "attempts": m[2]},
		})
		return
	}
	if m := reSudoCmd.FindStringSubmatch(msg); m != nil {
		for _, re := range riskySudo {
			if re.MatchString(m[3]) {
				cmd := engine.Truncate(m[3], 300)
				a.d.emit(event.Event{
					Category: event.PrivEsc, Severity: event.Medium, Detector: "auth",
					Key:     "sudo-risky|" + m[1] + "|" + m[3],
					Summary: fmt.Sprintf("Risky command via sudo by %s as %s", m[1], m[2]),
					User:    userEntity(m[1]),
					Process: &event.ProcessEntity{Cmdline: cmd},
					Fields: map[string]string{
						"user": m[1], "as_user": m[2], "command": cmd,
						"pattern": re.String(),
					},
				})
				return
			}
		}
	}
}

func (a *Auth) handleSu(l logsrc.Line) {
	m := reSuFailed.FindStringSubmatch(l.Msg)
	if m == nil {
		return
	}
	who := firstNonEmpty(m[2], m[4], m[5], "unknown")
	a.d.emit(event.Event{
		Category: event.PrivEsc, Severity: event.Medium, Detector: "auth", Key: "su-fail|" + who,
		Summary: fmt.Sprintf("Failed su attempt by %s", who),
		User:    userEntity(who),
		Fields:  map[string]string{"user": who, "log": engine.Truncate(l.Msg, 300)},
	})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
