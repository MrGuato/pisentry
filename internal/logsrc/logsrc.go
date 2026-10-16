// Package logsrc turns journald or classic syslog files into a stream of
// normalized lines for the auth and firewall detectors.
package logsrc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/metrics"
)

// Line is one normalized log record.
type Line struct {
	Time   time.Time
	Ident  string // sshd, sshd-session, sudo, su, kernel, ...
	Msg    string
	Kernel bool
	// UID of the logging process when known (journald), else -1. sshd always
	// logs from a root process, so a non-root sshd record is a forgery.
	UID int
}

// Start picks a source and returns a channel of lines. The channel closes when
// ctx is cancelled.
func Start(ctx context.Context, cfg *config.Config, m *metrics.Set, log *slog.Logger) (<-chan Line, string, error) {
	out := make(chan Line, 512)
	src := cfg.Logs.Source
	if src == "none" {
		close(out)
		return out, "none", nil
	}
	if src == "auto" {
		if journalAvailable(cfg) {
			src = "journald"
		} else {
			src = "file"
		}
	}
	switch src {
	case "journald":
		go runJournal(ctx, cfg, out, m, log)
	case "file":
		var files []string
		for _, f := range cfg.Logs.Files {
			if _, err := os.Stat(cfg.HostPath(f)); err == nil {
				files = append(files, cfg.HostPath(f))
			}
		}
		if len(files) == 0 {
			close(out)
			return out, src, errors.New("no log files found; auth and port-scan detection disabled")
		}
		done := make(chan struct{}, len(files))
		for _, f := range files {
			go func(p string) {
				tailFile(ctx, p, out, m, log)
				done <- struct{}{}
			}(f)
		}
		go func() {
			for range files {
				<-done
			}
			close(out)
		}()
		src = "file:" + strings.Join(files, ",")
	}
	return out, src, nil
}

func journalBinary(cfg *config.Config) string {
	for _, p := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		check := p
		if cfg.Logs.JournalChroot {
			check = cfg.HostPath(p)
		}
		if _, err := os.Stat(check); err == nil {
			return p
		}
	}
	return ""
}

func journalAvailable(cfg *config.Config) bool {
	if journalBinary(cfg) == "" {
		return false
	}
	for _, d := range []string{"/var/log/journal", "/run/log/journal"} {
		if _, err := os.Stat(cfg.HostPath(d)); err == nil {
			return true
		}
	}
	return false
}

// journalctl matches: same-field terms are OR'ed, "+" separates OR groups.
// OpenSSH 9.8+ logs as sshd-session, 10.x adds sshd-auth.
var journalArgs = []string{
	"--follow", "--output=json", "--lines=0", "--no-pager", "--quiet",
	"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth",
	"SYSLOG_IDENTIFIER=sudo", "SYSLOG_IDENTIFIER=su",
	"+", "_TRANSPORT=kernel",
}

type journalEntry struct {
	Message   json.RawMessage `json:"MESSAGE"`
	Ident     string          `json:"SYSLOG_IDENTIFIER"`
	Transport string          `json:"_TRANSPORT"`
	RealTime  string          `json:"__REALTIME_TIMESTAMP"`
	UID       string          `json:"_UID"`
}

func runJournal(ctx context.Context, cfg *config.Config, out chan<- Line, m *metrics.Set, log *slog.Logger) {
	defer close(out)
	backoff := time.Second
	for ctx.Err() == nil {
		runCtx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(runCtx, journalBinary(cfg), journalArgs...)
		// Minimal environment: the host binary must not inherit webhook secrets.
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
		if cfg.Logs.JournalChroot && cfg.HostRoot != "/" {
			// Run the host's own journalctl so the reader always understands
			// the host's journal file format.
			cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: cfg.HostRoot}
			cmd.Dir = "/"
		}
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			log.Error("journalctl start failed", "err", err)
			m.DetectorErrors.Inc("logsrc")
		} else {
			started := time.Now()
			readJournal(runCtx, stdout, out, m)
			// Kill before Wait: if the reader stopped early, journalctl would
			// otherwise block forever on a full pipe and Wait would never return.
			cancel()
			_ = cmd.Wait()
			if time.Since(started) > time.Minute {
				backoff = time.Second
			}
			if ctx.Err() == nil {
				log.Warn("journalctl exited, restarting", "backoff", backoff)
			}
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

const maxLine = 256 * 1024

func readJournal(ctx context.Context, r io.Reader, out chan<- Line, m *metrics.Set) {
	br := bufio.NewReaderSize(r, 64*1024)
	var buf []byte
	skipping := false
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return
		}
		if skipping {
			skipping = isPrefix
			continue
		}
		buf = append(buf, chunk...)
		if isPrefix {
			if len(buf) > maxLine {
				// Oversized record (a local user can craft these): drop it
				// instead of stalling the pipeline.
				buf, skipping = buf[:0], true
				m.DetectorErrors.Inc("logsrc_oversize")
			}
			continue
		}
		var e journalEntry
		if json.Unmarshal(buf, &e) == nil {
			if l, ok := FromJournal(e); ok {
				m.LogLines.Inc("journald")
				select {
				case out <- l:
				case <-ctx.Done():
					return
				}
			}
		}
		buf = buf[:0]
	}
}

// FromJournal converts one journal JSON record. MESSAGE is a string, or an
// array of bytes when it is not valid UTF-8.
func FromJournal(e journalEntry) (Line, bool) {
	var msg string
	if err := json.Unmarshal(e.Message, &msg); err != nil {
		var raw []byte
		var ints []int
		if json.Unmarshal(e.Message, &ints) != nil {
			return Line{}, false
		}
		for _, i := range ints {
			raw = append(raw, byte(i))
		}
		msg = string(raw)
	}
	l := Line{Ident: e.Ident, Msg: msg, Kernel: e.Transport == "kernel", Time: time.Now(), UID: -1}
	if u, err := parseInt(e.UID); err == nil && e.UID != "" {
		l.UID = int(u)
	}
	if l.Kernel && l.Ident == "" {
		l.Ident = "kernel"
	}
	if us, err := parseInt(e.RealTime); err == nil && us > 0 {
		l.Time = time.UnixMicro(us)
	}
	return l, true
}

func parseInt(s string) (int64, error) {
	var v int64
	_, err := fmt.Sscan(s, &v)
	return v, err
}

// syslogRe handles both "Oct 15 10:00:00 host ident[pid]: msg" and the
// RFC3339 "2026-10-15T10:00:00.123456-04:00 host ident[pid]: msg" format
// that rsyslog uses by default on Bookworm and Ubuntu 24.04.
var syslogRe = regexp.MustCompile(`^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:\s?(.*)$`)

// ParseSyslog normalizes one syslog-format line.
func ParseSyslog(s string) (Line, bool) {
	mm := syslogRe.FindStringSubmatch(s)
	if mm == nil {
		return Line{}, false
	}
	return Line{Time: time.Now(), Ident: mm[1], Msg: mm[2], Kernel: mm[1] == "kernel", UID: -1}, true
}

// tailFile follows a file from its current end, reopening on rotation.
func tailFile(ctx context.Context, path string, out chan<- Line, m *metrics.Set, log *slog.Logger) {
	var (
		f      *os.File
		rd     *bufio.Reader
		ino    uint64
		offset int64
		buf    string
	)
	open := func(seekEnd bool) {
		if f != nil {
			f.Close()
			f = nil
		}
		nf, err := os.Open(path)
		if err != nil {
			return
		}
		st, _ := nf.Stat()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			ino = uint64(sys.Ino)
		}
		offset = 0
		if seekEnd {
			offset, _ = nf.Seek(0, io.SeekEnd)
		}
		f, rd, buf = nf, bufio.NewReader(nf), ""
	}
	open(true)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if f != nil {
			for {
				chunk, err := rd.ReadString('\n')
				offset += int64(len(chunk))
				buf += chunk
				if err != nil {
					break
				}
				line := strings.TrimRight(buf, "\r\n")
				buf = ""
				if l, ok := ParseSyslog(line); ok {
					m.LogLines.Inc("file")
					select {
					case out <- l:
					case <-ctx.Done():
						return
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case <-tick.C:
		}
		// Rotation: inode changed, or file truncated below our offset.
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		var cur uint64
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			cur = uint64(sys.Ino)
		}
		if f == nil || cur != ino || st.Size() < offset {
			if f != nil {
				log.Info("log rotated, reopening", "path", path)
			}
			open(false)
		}
	}
}
