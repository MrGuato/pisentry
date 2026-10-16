package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
)

func put(t *testing.T, root, p, s string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, p)
	_ = os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
}

func TestSSHDIncludeFirstWins(t *testing.T) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.HostRoot = root
	// Pi OS / Ubuntu layout: Include at the top, drop-in overrides main file.
	put(t, root, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\nUsePAM yes\nMatch User backup\n  PasswordAuthentication yes\n", 0o644)
	put(t, root, "/etc/ssh/sshd_config.d/00-hardening.conf", "PasswordAuthentication no\nKbdInteractiveAuthentication no\n", 0o644)
	vals, ok := ParseSSHD(&cfg)
	if !ok {
		t.Fatal("not found")
	}
	if vals["passwordauthentication"] != "no" {
		t.Errorf("drop-in should win, got %q", vals["passwordauthentication"])
	}
	if vals["permitrootlogin"] != "yes" {
		t.Errorf("permitrootlogin %q", vals["permitrootlogin"])
	}
}

func find(fs []Finding, id string) Finding {
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	return Finding{}
}

func TestAuditAccounts(t *testing.T) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.HostRoot = root
	cfg.ProcRoot = filepath.Join(root, "proc")
	put(t, root, "/etc/ssh/sshd_config", "UsePAM yes\n", 0o644) // defaults: password + kbd on
	put(t, root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\npi:x:1000:1000::/home/pi:/bin/bash\nbackdoor:x:0:0::/:/bin/sh\n", 0o644)
	put(t, root, "/etc/shadow", "root:!:1::::::\npi:$y$j9T$abc:1::::::\nguest::1::::::\n", 0o644)
	put(t, root, "/etc/ld.so.preload", "/usr/lib/arm-linux-gnueabihf/libarmmem-${PLATFORM}.so\n", 0o644)
	fs := Run(&cfg)

	if f := find(fs, "SSH-01"); f.Status != Fail {
		t.Errorf("SSH-01 %+v", f)
	}
	if f := find(fs, "ACC-02"); f.Status != Fail || f.Detail != "accounts: backdoor" {
		t.Errorf("ACC-02 %+v", f)
	}
	if f := find(fs, "ACC-01"); f.Status != Fail || f.Detail != "accounts: guest" {
		t.Errorf("ACC-01 %+v", f)
	}
	if f := find(fs, "ACC-03"); f.Status != Fail || f.Severity != event.High {
		t.Errorf("ACC-03 %+v", f)
	}
	if f := find(fs, "FS-01"); f.Status != Fail {
		t.Errorf("FS-01 world-readable shadow: %+v", f)
	}
	if f := find(fs, "FS-02"); f.Status != Pass {
		t.Errorf("libarmmem preload is stock Raspbian, should pass: %+v", f)
	}
	if fs[0].Status != Fail || fs[0].Severity != event.Critical {
		t.Errorf("failing criticals should sort first, got %+v", fs[0])
	}
}
