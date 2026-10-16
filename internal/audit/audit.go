// Package audit implements the posture checks behind PS03 and parts of PS10.
// Checks only read files; they never change the system.
package audit

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/procfs"
)

const (
	Pass = "pass"
	Fail = "fail"
	Skip = "skip"
)

type Finding struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Category event.Category `json:"category"`
	Severity event.Severity `json:"severity"`
	Status   string         `json:"status"`
	Detail   string         `json:"detail,omitempty"`
	Fix      string         `json:"fix,omitempty"`
}

type checker struct {
	cfg *config.Config
	out []Finding
}

func (c *checker) add(f Finding) { c.out = append(c.out, f) }

func (c *checker) read(p string) (string, error) {
	b, err := os.ReadFile(c.cfg.HostPath(p))
	return string(b), err
}

// Run executes every check and returns findings sorted by severity then ID.
func Run(cfg *config.Config) []Finding {
	c := &checker{cfg: cfg}
	ssh := c.sshd()
	c.accounts(ssh)
	c.cleartext()
	c.autoUpdates()
	c.sysctls()
	c.files()
	sort.SliceStable(c.out, func(i, j int) bool {
		if c.out[i].Status != c.out[j].Status {
			return c.out[i].Status == Fail
		}
		if c.out[i].Severity != c.out[j].Severity {
			return c.out[i].Severity > c.out[j].Severity
		}
		return c.out[i].ID < c.out[j].ID
	})
	return c.out
}

// ---- SSH --------------------------------------------------------------

type sshdConf struct {
	present      bool
	vals         map[string]string
	passwordLike bool
	rootLogin    string
}

// ParseSSHD resolves the effective global sshd settings. sshd uses the first
// value it sees for a keyword, Include is expanded in place, and a Match block
// ends the global section.
func ParseSSHD(cfg *config.Config) (map[string]string, bool) {
	vals := map[string]string{}
	main := cfg.HostPath("/etc/ssh/sshd_config")
	if _, err := os.Stat(main); err != nil {
		return vals, false
	}
	parseSSHDFile(cfg, main, vals, 0)
	return vals, true
}

func parseSSHDFile(cfg *config.Config, path string, vals map[string]string, depth int) (stop bool) {
	if depth > 8 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Keyword and value may be separated by spaces, tabs or a single "=".
		parts := strings.Fields(strings.Replace(line, "=", " ", 1))
		kw := strings.ToLower(parts[0])
		rest := strings.Join(parts[1:], " ")
		switch kw {
		case "match":
			return true
		case "include":
			for _, pat := range strings.Fields(rest) {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join("/etc/ssh", pat)
				}
				matches, _ := filepath.Glob(cfg.HostPath(pat))
				sort.Strings(matches)
				for _, m := range matches {
					if parseSSHDFile(cfg, m, vals, depth+1) {
						return true
					}
				}
			}
			continue
		}
		if _, set := vals[kw]; !set {
			if fs := strings.Fields(rest); len(fs) > 0 {
				vals[kw] = strings.ToLower(fs[0])
			}
		}
	}
	return false
}

func val(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func (c *checker) sshd() sshdConf {
	vals, ok := ParseSSHD(c.cfg)
	s := sshdConf{present: ok, vals: vals}
	if !ok {
		for _, id := range []string{"SSH-01", "SSH-02", "SSH-03"} {
			c.add(Finding{ID: id, Title: "sshd not installed", Category: event.InsecurePosture, Status: Skip})
		}
		return s
	}
	pa := val(vals, "passwordauthentication", "yes")
	kbd := val(vals, "kbdinteractiveauthentication", val(vals, "challengeresponseauthentication", "yes"))
	pam := val(vals, "usepam", "no")
	s.passwordLike = pa == "yes" || (kbd == "yes" && pam == "yes")
	s.rootLogin = val(vals, "permitrootlogin", "prohibit-password")

	f := Finding{ID: "SSH-01", Title: "SSH password authentication enabled", Category: event.InsecurePosture, Severity: event.Medium,
		Fix: "After confirming key login works, create /etc/ssh/sshd_config.d/00-pisentry.conf with 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no', then reload sshd."}
	if s.passwordLike {
		f.Status = Fail
		f.Detail = fmt.Sprintf("PasswordAuthentication=%s KbdInteractiveAuthentication=%s UsePAM=%s", pa, kbd, pam)
		if s.rootLogin == "yes" {
			f.Severity = event.High
		}
	} else {
		f.Status = Pass
	}
	c.add(f)

	f = Finding{ID: "SSH-02", Title: "SSH root login permitted", Category: event.InsecurePosture, Severity: event.High,
		Fix: "Set 'PermitRootLogin no' (or prohibit-password if you need key-based root)."}
	f.Status = Pass
	if s.rootLogin == "yes" {
		f.Status, f.Detail = Fail, "PermitRootLogin yes"
	}
	c.add(f)

	f = Finding{ID: "SSH-03", Title: "SSH permits empty passwords", Category: event.InsecurePosture, Severity: event.Critical,
		Fix: "Set 'PermitEmptyPasswords no'."}
	f.Status = Pass
	if val(vals, "permitemptypasswords", "no") == "yes" {
		f.Status, f.Detail = Fail, "PermitEmptyPasswords yes"
	}
	c.add(f)
	return s
}

// ---- Accounts -----------------------------------------------------------

func (c *checker) accounts(ssh sshdConf) {
	passwd, perr := c.read("/etc/passwd")
	shadow, serr := c.read("/etc/shadow")

	// ACC-02: extra UID 0 accounts.
	f := Finding{ID: "ACC-02", Title: "Non-root account with UID 0", Category: event.FileTamper, Severity: event.Critical,
		Fix: "Investigate immediately. A second UID 0 account is a classic backdoor."}
	if perr != nil {
		f.Status = Skip
	} else {
		var extra []string
		for _, l := range strings.Split(passwd, "\n") {
			p := strings.Split(l, ":")
			if len(p) >= 3 && p[2] == "0" && p[0] != "root" {
				extra = append(extra, p[0])
			}
		}
		f.Status = Pass
		if len(extra) > 0 {
			f.Status, f.Detail = Fail, "accounts: "+strings.Join(extra, ", ")
		}
	}
	c.add(f)

	hashes := map[string]string{}
	if serr == nil {
		for _, l := range strings.Split(shadow, "\n") {
			p := strings.Split(l, ":")
			if len(p) >= 2 {
				hashes[p[0]] = p[1]
			}
		}
	}

	// ACC-01: accounts with an empty password field.
	f = Finding{ID: "ACC-01", Title: "Account with empty password", Category: event.InsecurePosture, Severity: event.Critical,
		Fix: "Lock the account with 'passwd -l <user>' or set a password."}
	if serr != nil {
		f.Status, f.Detail = Skip, "cannot read /etc/shadow"
	} else {
		var empty []string
		for u, h := range hashes {
			if h == "" {
				empty = append(empty, u)
			}
		}
		sort.Strings(empty)
		f.Status = Pass
		if len(empty) > 0 {
			f.Status, f.Detail = Fail, "accounts: "+strings.Join(empty, ", ")
		}
	}
	c.add(f)

	// ACC-03: the legacy default 'pi' account.
	f = Finding{ID: "ACC-03", Title: "Default 'pi' account has a usable password", Category: event.InsecurePosture, Severity: event.Low,
		Fix: "Rename or remove the pi account, or lock its password ('passwd -l pi') and use SSH keys. Mirai-style bots still try pi/raspberry."}
	h, exists := hashes["pi"]
	switch {
	case serr != nil:
		f.Status = Skip
	case !exists:
		f.Status, f.Detail = Pass, "no pi account"
	case usableHash(h):
		f.Status, f.Detail = Fail, "pi has a password hash"
		if ssh.passwordLike {
			f.Severity, f.Detail = event.High, "pi has a password and SSH password auth is on"
		}
	default:
		f.Status, f.Detail = Pass, "pi account is locked"
	}
	c.add(f)
}

func usableHash(h string) bool {
	return h != "" && !strings.HasPrefix(h, "!") && !strings.HasPrefix(h, "*")
}

// ---- Network ------------------------------------------------------------

var cleartextPorts = map[int]string{21: "ftp", 23: "telnet", 69: "tftp", 512: "rexec", 513: "rlogin", 514: "rsh"}

func (c *checker) cleartext() {
	f := Finding{ID: "NET-01", Title: "Cleartext remote-access service listening", Category: event.InsecurePosture, Severity: event.High,
		Fix: "Disable telnet/ftp/r-services and use SSH."}
	socks, err := procfs.ReadNet(c.cfg.ProcRoot, "1")
	if err != nil {
		socks, err = procfs.ReadNet(c.cfg.ProcRoot, "")
	}
	if err != nil {
		f.Status = Skip
		c.add(f)
		return
	}
	var hits []string
	seen := map[string]bool{}
	for _, s := range socks {
		if !s.IsListener() || s.Local.Addr().IsLoopback() {
			continue
		}
		port := int(s.Local.Port())
		if name, ok := cleartextPorts[port]; ok {
			if (name == "tftp") != strings.HasPrefix(s.Proto, "udp") {
				continue
			}
			k := fmt.Sprintf("%s/%d", name, port)
			if !seen[k] {
				seen[k] = true
				hits = append(hits, k)
			}
		}
	}
	sort.Strings(hits)
	f.Status = Pass
	if len(hits) > 0 {
		f.Status, f.Detail = Fail, strings.Join(hits, ", ")
	}
	c.add(f)
}

// ---- Updates ------------------------------------------------------------

func (c *checker) autoUpdates() {
	f := Finding{ID: "UPD-01", Title: "Automatic security updates not enabled", Category: event.InsecurePosture, Severity: event.Low,
		Fix: "Debian/Ubuntu/Pi OS: apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades. RHEL: dnf install dnf-automatic && systemctl enable --now dnf-automatic-install.timer."}
	exists := func(p string) bool { _, err := os.Stat(c.cfg.HostPath(p)); return err == nil }
	switch {
	case exists("/etc/apt"):
		txt := ""
		matches, _ := filepath.Glob(c.cfg.HostPath("/etc/apt/apt.conf.d/*"))
		for _, m := range matches {
			if b, err := os.ReadFile(m); err == nil {
				txt += string(b) + "\n"
			}
		}
		if strings.Contains(txt, `APT::Periodic::Unattended-Upgrade "1"`) && exists("/usr/bin/unattended-upgrade") {
			f.Status = Pass
		} else {
			f.Status, f.Detail = Fail, "unattended-upgrades not installed or not enabled"
		}
	case exists("/etc/dnf"):
		wants, _ := filepath.Glob(c.cfg.HostPath("/etc/systemd/system/timers.target.wants/dnf-automatic*.timer"))
		if len(wants) > 0 {
			f.Status = Pass
		} else {
			f.Status, f.Detail = Fail, "dnf-automatic timer not enabled"
		}
	default:
		f.Status, f.Detail = Skip, "unknown package manager"
	}
	c.add(f)
}

// ---- Kernel -------------------------------------------------------------

func (c *checker) sysctls() {
	type sc struct {
		id, key, title string
		sev            event.Severity
		ok             func(int) bool
		want           string
	}
	checks := []sc{
		{"KRN-01", "kernel/randomize_va_space", "ASLR not fully enabled", event.Medium, func(v int) bool { return v == 2 }, "2"},
		{"KRN-02", "fs/protected_symlinks", "Symlink protection disabled", event.Medium, func(v int) bool { return v == 1 }, "1"},
		{"KRN-03", "fs/protected_hardlinks", "Hardlink protection disabled", event.Medium, func(v int) bool { return v == 1 }, "1"},
		{"KRN-04", "kernel/kptr_restrict", "Kernel pointers exposed to users", event.Low, func(v int) bool { return v >= 1 }, ">=1"},
		{"KRN-05", "kernel/dmesg_restrict", "dmesg readable by unprivileged users", event.Low, func(v int) bool { return v == 1 }, "1"},
		{"KRN-06", "kernel/unprivileged_bpf_disabled", "Unprivileged eBPF allowed", event.Low, func(v int) bool { return v >= 1 }, ">=1"},
	}
	for _, s := range checks {
		f := Finding{ID: s.id, Title: s.title, Category: event.InsecurePosture, Severity: s.sev,
			Fix: fmt.Sprintf("echo '%s = %s' | sudo tee -a /etc/sysctl.d/90-hardening.conf && sudo sysctl --system", strings.ReplaceAll(s.key, "/", "."), strings.TrimPrefix(s.want, ">="))}
		b, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot, "sys", s.key))
		if err != nil {
			f.Status = Skip
			c.add(f)
			continue
		}
		v, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if s.ok(v) {
			f.Status = Pass
		} else {
			f.Status, f.Detail = Fail, fmt.Sprintf("%s = %d (want %s)", strings.ReplaceAll(s.key, "/", "."), v, s.want)
		}
		c.add(f)
	}
}

// ---- File permissions ---------------------------------------------------

func (c *checker) files() {
	// FS-01: /etc/shadow readable by everyone.
	f := Finding{ID: "FS-01", Title: "/etc/shadow is world-readable", Category: event.FileTamper, Severity: event.Critical,
		Fix: "chmod 640 /etc/shadow (Debian: root:shadow) or 000 (RHEL)."}
	if fi, err := os.Stat(c.cfg.HostPath("/etc/shadow")); err != nil {
		f.Status = Skip
	} else if fi.Mode().Perm()&0o004 != 0 {
		f.Status, f.Detail = Fail, fi.Mode().Perm().String()
	} else {
		f.Status = Pass
	}
	c.add(f)

	// FS-02: ld.so.preload with anything other than Raspbian's libarmmem.
	f = Finding{ID: "FS-02", Title: "/etc/ld.so.preload injects a library into every process", Category: event.FileTamper, Severity: event.High,
		Fix: "Verify every listed library. Userland rootkits (Azazel, Jynx, bdvl) live here."}
	if b, err := c.read("/etc/ld.so.preload"); err != nil {
		f.Status = Pass
	} else {
		var odd []string
		for _, l := range strings.Fields(b) {
			if !strings.HasPrefix(l, "#") && !strings.Contains(l, "libarmmem") {
				odd = append(odd, l)
			}
		}
		f.Status = Pass
		if len(odd) > 0 {
			f.Status, f.Detail = Fail, strings.Join(odd, " ")
		}
	}
	c.add(f)

	// SSH-04: authorized_keys writable by group or others.
	f = Finding{ID: "SSH-04", Title: "authorized_keys writable by other users", Category: event.Persistence, Severity: event.High,
		Fix: "chmod 600 ~/.ssh/authorized_keys and chmod 700 ~/.ssh"}
	var bad []string
	pats := []string{"/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"}
	for _, p := range pats {
		matches, _ := filepath.Glob(c.cfg.HostPath(p))
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err == nil && fi.Mode().Perm()&0o022 != 0 {
				bad = append(bad, c.cfg.StripHost(m)+" "+fi.Mode().Perm().String())
			}
			if di, err := os.Stat(filepath.Dir(m)); err == nil && di.Mode().Perm()&fs.FileMode(0o022) != 0 {
				bad = append(bad, c.cfg.StripHost(filepath.Dir(m))+" "+di.Mode().Perm().String())
			}
		}
	}
	f.Status = Pass
	if len(bad) > 0 {
		f.Status, f.Detail = Fail, strings.Join(bad, "; ")
	}
	c.add(f)
}
