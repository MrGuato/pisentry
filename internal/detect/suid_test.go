package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
)

// Uses plain data files with mode bits set; nothing here is executable.
func TestSUIDScan(t *testing.T) {
	root := t.TempDir()
	d, s, _ := newDeps(t, func(c *config.Config) {
		c.HostRoot = root
		c.SUID.Paths = []string{"/usr/bin", "/tmp"}
	})
	mk := func(p string, mode os.FileMode) {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte("data "+p), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("/usr/bin/passwd", 0o644|os.ModeSetuid)
	mk("/usr/bin/ls", 0o644)
	sc := NewSUID(d)
	if err := sc.Scan(); err != nil || len(s.evs) != 0 {
		t.Fatalf("baseline should be silent: %v %+v", err, s.evs)
	}
	mk("/usr/bin/newtool", 0o644|os.ModeSetgid)
	mk("/tmp/x/bash", 0o644|os.ModeSetuid)
	_ = sc.Scan()
	got := map[string]event.Severity{}
	for _, e := range s.evs {
		got[e.Fields["path"]] = e.Severity
	}
	// The files are owned by whoever runs the test: root locally, a normal
	// user on GitHub runners. Expect whatever the severity rule says for that.
	uid := os.Geteuid()
	for _, p := range []string{"/usr/bin/newtool", "/tmp/x/bash"} {
		want, _ := newSUIDSeverity(p, uid)
		if got[p] != want {
			t.Errorf("%s: got %v, want %v (uid %d)", p, got[p], want, uid)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %+v", got)
	}
}

// The severity rule itself, independent of who runs the test.
func TestNewSUIDSeverity(t *testing.T) {
	cases := []struct {
		path string
		uid  int
		want event.Severity
	}{
		{"/usr/bin/newtool", 0, event.High},
		{"/tmp/x/payload", 0, event.Critical},
		{"/usr/local/bin/bash", 0, event.Critical},
		{"/home/eve/bash", 1000, event.Medium},
		{"/usr/bin/newtool", 1000, event.Medium},
	}
	for _, c := range cases {
		if got, _ := newSUIDSeverity(c.path, c.uid); got != c.want {
			t.Errorf("%s uid=%d: got %v want %v", c.path, c.uid, got, c.want)
		}
	}
}
