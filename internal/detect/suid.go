package detect

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/state"
)

// Binaries that give an instant root shell when setuid (see GTFOBins).
var gtfoSUID = []string{
	"bash", "sh", "dash", "zsh", "ash", "ksh", "busybox", "python", "python3", "perl", "ruby",
	"php", "lua", "node", "find", "vim", "vi", "nano", "less", "more", "awk", "gawk", "nmap",
	"env", "tar", "zip", "cp", "mv", "tee", "dd", "socat", "nc", "ncat", "gdb", "strace",
	"docker", "systemctl", "journalctl", "openssl", "wget", "curl", "rsync", "git", "make",
}

// newSUIDSeverity rates a setuid/setgid file that was not in the baseline.
// Only root-owned setuid files grant root. Any user can chmod u+s their own
// file, so those stay Medium to keep alerts meaningful.
func newSUIDSeverity(path string, ownerUID int) (event.Severity, string) {
	if ownerUID != 0 {
		return event.Medium, "setuid/setgid file owned by a non-root user"
	}
	if contains(gtfoSUID, filepath.Base(path)) {
		return event.Critical, "root setuid shell/interpreter or GTFOBins binary"
	}
	for _, d := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/"} {
		if strings.HasPrefix(path, d) {
			return event.Critical, "root setuid file in a user-writable location"
		}
	}
	return event.High, ""
}

// SUID covers the SUID/SGID half of PS04 with a periodic filesystem walk.
type SUID struct{ d Deps }

func NewSUID(d Deps) *SUID { return &SUID{d: d} }

func (s *SUID) Run(ctx context.Context) {
	Loop(ctx, s.d, "suid", s.d.Cfg.SUID.Interval.Duration, s.Scan)
}

// Walk returns every setuid/setgid regular file under the configured paths.
func (s *SUID) Walk() map[string]state.FileSig {
	cfg := s.d.Cfg
	out := map[string]state.FileSig{}
	for _, root := range cfg.SUID.Paths {
		real := cfg.HostPath(root)
		fi, err := os.Lstat(real)
		if err != nil || !fi.IsDir() { // skips merged-usr symlinks like /bin -> usr/bin
			continue
		}
		_ = filepath.WalkDir(real, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				if de != nil && de.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if de.IsDir() {
				switch de.Name() {
				case "node_modules", ".cache", "proc", "sys":
					return filepath.SkipDir
				}
				return nil
			}
			if !de.Type().IsRegular() {
				return nil
			}
			info, err := de.Info()
			if err != nil || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
				return nil
			}
			if sig, err := Sig(p); err == nil {
				out[cfg.StripHost(p)] = sig
			}
			return nil
		})
	}
	return out
}

func (s *SUID) Scan() error {
	cur := s.Walk()
	var (
		base  map[string]state.FileSig
		ready bool
	)
	s.d.Store.View(func(st *state.State) {
		ready = st.Baselines.SUIDReady
		base = st.Baselines.SUID
	})
	s.d.M.BaselineFiles.Set(float64(len(cur)), "suid")
	if !ready {
		s.d.Store.Update(func(st *state.State) {
			st.Baselines.SUID, st.Baselines.SUIDReady = cur, true
		})
		s.d.Log.Info("suid baseline created", "files", len(cur))
		return nil
	}
	paths := make([]string, 0, len(cur))
	for p := range cur {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sig := cur[p]
		old, existed := base[p]
		if existed && old.Hash == sig.Hash && old.Mode == sig.Mode {
			continue
		}
		bit := "setuid"
		if fs.FileMode(sig.Mode)&fs.ModeSetuid == 0 {
			bit = "setgid"
		}
		fields := map[string]string{
			"path": p, "bit": bit, "mode": fs.FileMode(sig.Mode).String(),
			"sha256": short(sig.Hash), "owner_uid": fmt.Sprint(sig.UID),
		}
		var sev event.Severity
		var summary string
		switch {
		case !existed:
			summary = fmt.Sprintf("New %s binary %s", bit, p)
			var reason string
			sev, reason = newSUIDSeverity(p, sig.UID)
			if reason != "" {
				fields["reason"] = reason
			}
		default:
			sev = event.Medium
			summary = fmt.Sprintf("%s binary %s changed (package update or replacement)", bit, p)
			fields["old_sha256"] = short(old.Hash)
		}
		s.d.Emit.Emit(event.Event{
			Category: event.PrivEsc, Severity: sev, Detector: "suid", Key: p + "|" + sig.Hash,
			Summary: summary, Fields: fields,
		})
	}
	s.d.Store.Update(func(st *state.State) { st.Baselines.SUID = cur })
	return nil
}
