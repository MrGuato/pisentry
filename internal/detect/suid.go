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
	"github.com/MrGuato/pisentry/internal/rules"
	"github.com/MrGuato/pisentry/internal/state"
)

// newSUIDSeverity rates a setuid/setgid file that was not in the baseline.
// Only root-owned setuid files grant root. Any user can chmod u+s their own
// file, so those stay Medium to keep alerts meaningful.
func newSUIDSeverity(path string, ownerUID int) (event.Severity, string) {
	return newSUIDSeverityWithList(path, ownerUID, rules.Default().Catalog().GTFOSUID)
}

func newSUIDSeverityWithList(path string, ownerUID int, gtfo []string) (event.Severity, string) {
	if ownerUID != 0 {
		return event.Medium, "setuid/setgid file owned by a non-root user"
	}
	if contains(gtfo, filepath.Base(path)) {
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
// The walk runs at idle disk priority: on a Pi the root filesystem is often
// an SD card shared with databases (k3s, Postgres) that must not stall.
func (s *SUID) Walk() map[string]state.FileSig {
	defer idleIO()()
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
			sev, reason = newSUIDSeverityWithList(p, sig.UID, s.d.rules().Catalog().GTFOSUID)
			if reason != "" {
				fields["reason"] = reason
			}
		default:
			sev = event.Medium
			summary = fmt.Sprintf("%s binary %s changed (package update or replacement)", bit, p)
			fields["old_sha256"] = short(old.Hash)
		}
		s.d.emit(event.Event{
			Category: event.PrivEsc, Severity: sev, Detector: "suid", Key: p + "|" + sig.Hash,
			Summary: summary,
			File: &event.FileEntity{
				Path:       p,
				HashBefore: short(old.Hash),
				HashAfter:  short(sig.Hash),
			},
			User:   &event.UserEntity{UID: event.IntPtr(sig.UID)},
			Fields: fields,
		})
	}
	s.d.Store.Update(func(st *state.State) { st.Baselines.SUID = cur })
	return nil
}
