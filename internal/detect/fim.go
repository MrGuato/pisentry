package detect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/engine"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/procfs"
	"github.com/MrGuato/pisentry/internal/state"
)

// DefaultWatches is the FIM watch list. Order matters: the first matching
// spec decides a path's category and severity, so specific entries come first.
func DefaultWatches() []config.WatchSpec {
	w := func(p string, c event.Category, s event.Severity, rec bool) config.WatchSpec {
		return config.WatchSpec{Pattern: p, Category: c, Severity: s, Recursive: rec}
	}
	C, H, M, L := event.Critical, event.High, event.Medium, event.Low
	return []config.WatchSpec{
		// PS10 critical files
		w("/etc/ld.so.preload", event.FileTamper, C, false),
		w("/etc/ssh/sshd_config", event.FileTamper, H, false),
		w("/etc/ssh/sshd_config.d", event.FileTamper, H, false),
		w("/etc/pam.d", event.FileTamper, H, false),
		w("/etc/ld.so.conf", event.FileTamper, M, false),
		w("/etc/ld.so.conf.d", event.FileTamper, M, false),
		w("/etc/passwd", event.FileTamper, M, false),
		w("/etc/shadow", event.FileTamper, M, false),
		w("/etc/group", event.FileTamper, M, false),
		w("/etc/gshadow", event.FileTamper, L, false),
		w("/etc/nsswitch.conf", event.FileTamper, M, false),
		w("/etc/hosts", event.FileTamper, L, false),
		// PS04 privilege escalation
		w("/etc/sudoers", event.PrivEsc, H, false),
		w("/etc/sudoers.d", event.PrivEsc, H, false),
		// PS05 persistence
		w("/root/.ssh/authorized_keys", event.Persistence, H, false),
		w("/root/.ssh/authorized_keys2", event.Persistence, H, false),
		w("/home/*/.ssh/authorized_keys", event.Persistence, H, false),
		w("/home/*/.ssh/authorized_keys2", event.Persistence, H, false),
		w("/etc/crontab", event.Persistence, H, false),
		w("/etc/cron.d", event.Persistence, H, false),
		w("/var/spool/cron/crontabs", event.Persistence, H, false),
		w("/var/spool/cron", event.Persistence, H, false),
		w("/etc/rc.local", event.Persistence, H, false),
		w("/root/.config/systemd/user", event.Persistence, H, true),
		w("/home/*/.config/systemd/user", event.Persistence, H, true),
		w("/etc/cron.hourly", event.Persistence, M, false),
		w("/etc/cron.daily", event.Persistence, M, false),
		w("/etc/cron.weekly", event.Persistence, M, false),
		w("/etc/cron.monthly", event.Persistence, M, false),
		w("/etc/systemd/system", event.Persistence, M, true),
		w("/etc/init.d", event.Persistence, M, false),
		w("/etc/udev/rules.d", event.Persistence, M, false),
		w("/etc/xdg/autostart", event.Persistence, M, false),
		w("/etc/update-motd.d", event.Persistence, M, false),
		w("/etc/profile", event.Persistence, M, false),
		w("/etc/profile.d", event.Persistence, M, false),
		w("/etc/bash.bashrc", event.Persistence, M, false),
		w("/etc/environment", event.Persistence, M, false),
		w("/root/.bashrc", event.Persistence, M, false),
		w("/root/.profile", event.Persistence, M, false),
		w("/home/*/.bashrc", event.Persistence, M, false),
		w("/home/*/.profile", event.Persistence, M, false),
		w("/home/*/.bash_profile", event.Persistence, M, false),
	}
}

var pkgManagers = []string{"apt", "apt-get", "dpkg", "unattended-upgr", "dnf", "yum", "rpm", "packagekitd", "snapd"}

var privGroups = []string{"root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "disk", "shadow"}

// FIM covers PS10 critical files, PS05 persistence locations and sudoers (PS04).
type FIM struct {
	d     Deps
	specs []config.WatchSpec
}

func NewFIM(d Deps) *FIM {
	return &FIM{d: d, specs: append(DefaultWatches(), d.Cfg.FIM.ExtraWatch...)}
}

func (f *FIM) Run(ctx context.Context) {
	Loop(ctx, f.d, "fim", f.d.Cfg.FIM.Interval.Duration, f.Scan)
}

type fimEntry struct {
	sig  state.FileSig
	spec int
}

const maxHashSize = 8 << 20

// maxPerWatch caps files per watch spec so a user cannot make FIM hash
// thousands of files every cycle by filling ~/.config/systemd/user.
const maxPerWatch = 500

var errNotRegular = errors.New("not a regular file")

// openRegular opens a file without following symlinks and without blocking on
// a FIFO (a local user can swap authorized_keys for a named pipe), and refuses
// anything that is not a regular file once opened.
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// Sig fingerprints one path without following symlinks.
func Sig(path string) (state.FileSig, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return state.FileSig{}, err
	}
	s := state.FileSig{Mode: uint32(fi.Mode()), Size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.UID = int(st.Uid)
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		s.Link, _ = os.Readlink(path)
	case fi.Mode().IsRegular():
		if fi.Size() > maxHashSize {
			s.Hash = fmt.Sprintf("mtime:%d", fi.ModTime().UnixNano())
			break
		}
		fh, err := openRegular(path)
		if err != nil {
			return s, err
		}
		h := sha256.New()
		_, err = io.Copy(h, fh)
		fh.Close()
		if err != nil {
			return s, err
		}
		s.Hash = hex.EncodeToString(h.Sum(nil))
	}
	return s, nil
}

func (f *FIM) snapshot() map[string]fimEntry {
	cfg := f.d.Cfg
	out := map[string]fimEntry{}
	perSpec := map[int]int{}
	add := func(real string, idx int) {
		host := cfg.StripHost(real)
		if _, dup := out[host]; dup {
			return
		}
		if perSpec[idx] >= maxPerWatch {
			if perSpec[idx] == maxPerWatch {
				f.d.Log.Warn("fim watch hit file cap, extra files ignored", "pattern", f.specs[idx].Pattern, "cap", maxPerWatch)
				perSpec[idx]++
			}
			return
		}
		perSpec[idx]++
		if sig, err := Sig(real); err == nil {
			out[host] = fimEntry{sig: sig, spec: idx}
		}
	}
	for i, sp := range f.specs {
		matches, _ := filepath.Glob(cfg.HostPath(sp.Pattern))
		for _, m := range matches {
			fi, err := os.Lstat(m)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				add(m, i)
				continue
			}
			base := strings.Count(m, string(os.PathSeparator))
			_ = filepath.WalkDir(m, func(p string, de fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if de.IsDir() {
					if p == m {
						return nil
					}
					if !sp.Recursive || strings.Count(p, string(os.PathSeparator))-base > 3 {
						return filepath.SkipDir
					}
					return nil
				}
				add(p, i)
				return nil
			})
		}
	}
	return out
}

// Scan diffs the watch set against the baseline and emits one event per change.
func (f *FIM) Scan() error {
	cur := f.snapshot()
	var (
		base  map[string]state.FileSig
		ready bool
	)
	f.d.Store.View(func(s *state.State) {
		ready = s.Baselines.FIMReady
		base = make(map[string]state.FileSig, len(s.Baselines.FIM))
		for k, v := range s.Baselines.FIM {
			base[k] = v
		}
	})
	newBase := make(map[string]state.FileSig, len(cur))
	for k, v := range cur {
		newBase[k] = v.sig
	}
	accounts, groups := f.readAccounts()
	if !ready {
		f.d.Store.Update(func(s *state.State) {
			s.Baselines.FIM, s.Baselines.FIMReady = newBase, true
			s.Baselines.Accounts, s.Baselines.PrivGroups = accounts, groups
		})
		f.d.M.BaselineFiles.Set(float64(len(newBase)), "fim")
		f.d.Log.Info("fim baseline created", "files", len(newBase))
		return nil
	}

	pm := ""
	changed := false
	paths := make([]string, 0, len(cur)+len(base))
	for p := range cur {
		paths = append(paths, p)
	}
	for p := range base {
		if _, ok := cur[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		old, hadOld := base[p]
		ne, hasNew := cur[p]
		var change string
		switch {
		case !hadOld && hasNew:
			change = "created"
		case hadOld && !hasNew:
			change = "deleted"
		case old != ne.sig:
			change = "modified"
		default:
			continue
		}
		if !changed {
			pm = procfs.AnyComm(f.d.Cfg.ProcRoot, pkgManagers...)
			changed = true
		}
		f.report(p, change, old, ne, hasNew, pm)
	}
	if changed {
		f.diffAccounts(accounts, groups)
	}
	f.d.Store.Update(func(s *state.State) {
		s.Baselines.FIM = newBase
		s.Baselines.Accounts, s.Baselines.PrivGroups = accounts, groups
	})
	f.d.M.BaselineFiles.Set(float64(len(newBase)), "fim")
	return nil
}

func (f *FIM) specFor(path string, hint int, hasHint bool) config.WatchSpec {
	if hasHint {
		return f.specs[hint]
	}
	for _, sp := range f.specs {
		cand := path
		for depth := 0; cand != "/" && cand != "."; depth++ {
			if ok, _ := filepath.Match(sp.Pattern, cand); ok && (depth == 0 || depth == 1 || sp.Recursive) {
				return sp
			}
			cand = filepath.Dir(cand)
		}
	}
	return config.WatchSpec{Category: event.FileTamper, Severity: event.Medium}
}

func (f *FIM) report(path, change string, old state.FileSig, ne fimEntry, hasNew bool, pm string) {
	sp := f.specFor(path, ne.spec, hasNew)
	sev := sp.Severity
	fields := map[string]string{"path": path, "change": change}
	if hasNew {
		fields["mode"] = fs.FileMode(ne.sig.Mode).String()
		fields["uid"] = strconv.Itoa(ne.sig.UID)
		if ne.sig.Hash != "" {
			fields["sha256"] = short(ne.sig.Hash)
		}
		if ne.sig.Link != "" {
			fields["link_target"] = ne.sig.Link
		}
	}
	if old.Hash != "" {
		fields["old_sha256"] = short(old.Hash)
	}
	if change == "deleted" {
		sev = event.Low
	}
	switch {
	case path == "/etc/ld.so.preload" && hasNew && ne.sig.Size > 0:
		sev = event.Critical
		if b, err := readRegular(f.d.Cfg.HostPath(path), 4096); err == nil {
			fields["content"] = engine.Truncate(strings.TrimSpace(string(b)), 300)
		}
	case strings.HasSuffix(path, "authorized_keys") || strings.HasSuffix(path, "authorized_keys2"):
		if hasNew {
			fields["keys"] = strconv.Itoa(countKeys(f.d.Cfg.HostPath(path)))
		}
		if strings.HasPrefix(path, "/root/") && change != "deleted" {
			sev = event.Critical
		}
	case path == "/etc/passwd" || path == "/etc/group":
		// Account and group semantics are reported by diffAccounts; only
		// emit the raw file change at low severity for the audit trail.
		sev = event.Low
	}
	if pm != "" && sev > event.Low && sev < event.Critical {
		sev = sev.Bump(-1)
		fields["package_manager_active"] = pm
	}
	fe := &event.FileEntity{
		Path:       path,
		HashBefore: short(old.Hash),
		HashAfter:  fields["sha256"],
	}
	var ue *event.UserEntity
	if hasNew {
		ue = &event.UserEntity{UID: event.IntPtr(ne.sig.UID)}
	}
	f.d.emit(event.Event{
		Category: sp.Category, Severity: sev, Detector: "fim",
		Key:     path + "|" + change + "|" + fields["sha256"],
		Summary: fmt.Sprintf("%s %s", path, change),
		File:    fe,
		User:    ue,
		Fields:  fields,
	})
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func countKeys(path string) int {
	fh, err := openRegular(path)
	if err != nil {
		return 0
	}
	defer fh.Close()
	n := 0
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}

// readAccounts parses /etc/passwd into user -> "uid:shell" and the members of
// privileged groups from /etc/group (supplementary members plus primary gid).
func (f *FIM) readAccounts() (map[string]string, map[string][]string) {
	acc := map[string]string{}
	primary := map[string][]string{} // gid -> users
	if b, err := os.ReadFile(f.d.Cfg.HostPath("/etc/passwd")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			p := strings.Split(l, ":")
			if len(p) < 7 || strings.HasPrefix(l, "#") {
				continue
			}
			acc[p[0]] = p[2] + ":" + p[6]
			primary[p[3]] = append(primary[p[3]], p[0])
		}
	}
	groups := map[string][]string{}
	if b, err := os.ReadFile(f.d.Cfg.HostPath("/etc/group")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			p := strings.Split(l, ":")
			if len(p) < 4 || !contains(privGroups, p[0]) {
				continue
			}
			var mem []string
			for _, u := range strings.Split(p[3], ",") {
				if u = strings.TrimSpace(u); u != "" {
					mem = append(mem, u)
				}
			}
			mem = append(mem, primary[p[2]]...)
			sort.Strings(mem)
			groups[p[0]] = dedupe(mem)
		}
	}
	return acc, groups
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func loginShell(sh string) bool {
	return sh != "" && !strings.HasSuffix(sh, "nologin") && !strings.HasSuffix(sh, "/false") && sh != "/bin/sync"
}

func (f *FIM) diffAccounts(acc map[string]string, groups map[string][]string) {
	var oldAcc map[string]string
	var oldGroups map[string][]string
	f.d.Store.View(func(s *state.State) {
		oldAcc, oldGroups = s.Baselines.Accounts, s.Baselines.PrivGroups
	})
	if len(oldAcc) == 0 {
		return
	}
	users := make([]string, 0, len(acc))
	for u := range acc {
		users = append(users, u)
	}
	sort.Strings(users)
	for _, u := range users {
		v := acc[u]
		uid, shell, _ := strings.Cut(v, ":")
		prev, existed := oldAcc[u]
		if existed && prev == v {
			continue
		}
		prevUID, prevShell, _ := strings.Cut(prev, ":")
		fields := map[string]string{"user": u, "uid": uid, "shell": shell}
		switch {
		case uid == "0" && u != "root" && (!existed || prevUID != "0"):
			f.emitAcct(event.FileTamper, event.Critical, u, uid, "/etc/passwd", "uid0", fmt.Sprintf("Account %s now has UID 0 (root equivalent)", u), fields)
		case !existed && loginShell(shell):
			f.emitAcct(event.FileTamper, event.High, u, uid, "/etc/passwd", "new-login", fmt.Sprintf("New login account %s created (shell %s)", u, shell), fields)
		case !existed:
			f.emitAcct(event.FileTamper, event.Low, u, uid, "/etc/passwd", "new-system", fmt.Sprintf("New non-login account %s created", u), fields)
		case !loginShell(prevShell) && loginShell(shell):
			fields["old_shell"] = prevShell
			f.emitAcct(event.Persistence, event.High, u, uid, "/etc/passwd", "shell", fmt.Sprintf("Service account %s was given a login shell (%s)", u, shell), fields)
		default:
			fields["old"] = prev
			f.emitAcct(event.FileTamper, event.Medium, u, uid, "/etc/passwd", "changed", fmt.Sprintf("Account %s changed", u), fields)
		}
	}
	for g, mem := range groups {
		for _, u := range mem {
			if !contains(oldGroups[g], u) {
				uid, _, _ := strings.Cut(acc[u], ":")
				f.emitAcct(event.PrivEsc, event.High, u, uid, "/etc/group", "group-"+g,
					fmt.Sprintf("User %s added to privileged group %s", u, g),
					map[string]string{"user": u, "group": g})
			}
		}
	}
}

func (f *FIM) emitAcct(c event.Category, sev event.Severity, user, uidStr, filePath, kind, summary string, fields map[string]string) {
	ue := &event.UserEntity{Name: user}
	if n, err := strconv.Atoi(uidStr); err == nil && n >= 0 {
		ue.UID = event.IntPtr(n)
	}
	f.d.emit(event.Event{
		Category: c, Severity: sev, Detector: "fim", Key: "acct|" + kind + "|" + user,
		Summary: summary,
		User:    ue,
		File:    &event.FileEntity{Path: filePath},
		Fields:  fields,
	})
}
