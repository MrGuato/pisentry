package detect

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/rules"
)

const webShellBundle = `{
  "schema_version": 1,
  "rules": [
    {
      "id": "TEST-WEB-SHELL",
      "title": "Shell spawned by a web server",
      "category": "PS08",
      "level": "high",
      "mitre": ["T1505.003"],
      "source": "process",
      "match": {"all": [
        {"field": "process.comm", "equals": ["sh"]},
        {"field": "process.parent_comm", "equals": ["nginx"]}
      ]}
    },
    {
      "id": "TEST-MINER",
      "title": "Known miner",
      "category": "PS06",
      "level": "critical",
      "mitre": ["T1496"],
      "source": "process",
      "match": {"all": [{"field": "process.comm", "equals": ["xmrig"]}]}
    }
  ]
}`

func writeProc(t *testing.T, procRoot string, pid, ppid int, comm, exe string) {
	t.Helper()
	p := strconv.Itoa(pid)
	writeFile(t, procRoot, "/"+p+"/stat", p+" ("+comm+") S "+strconv.Itoa(ppid)+" "+p+" "+p+" 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 1000 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	writeFile(t, procRoot, "/"+p+"/cmdline", comm+"\x00")
	writeFile(t, procRoot, "/"+p+"/status", "Name:\t"+comm+"\nUid:\t33\t33\t33\t33\n")
	if err := os.Symlink(exe, filepath.Join(procRoot, p, "exe")); err != nil {
		t.Fatal(err)
	}
}

// A rule that matches on process.parent_comm must fire even though the parent
// is only read lazily, and a non-PS06 hit must not be reported as a miner.
func TestProcRulesNonMinerCategory(t *testing.T) {
	procRoot := filepath.Join(t.TempDir(), "proc")
	d, s, _ := newDeps(t, func(cfg *config.Config) { cfg.ProcRoot = procRoot })
	re, err := rules.NewEngineFromBytes("test.json", []byte(webShellBundle))
	if err != nil {
		t.Fatal(err)
	}
	d.Rules = re

	writeProc(t, procRoot, 700, 1, "nginx", "/usr/sbin/nginx")
	writeProc(t, procRoot, 701, 700, "sh", "/usr/bin/dash")
	writeProc(t, procRoot, 702, 1, "sh", "/usr/bin/dash") // same comm, wrong parent
	writeProc(t, procRoot, 703, 1, "xmrig", "/tmp/xmrig")

	pw := NewProcWatch(d)
	if err := pw.Scan(); err != nil {
		t.Fatal(err)
	}
	_ = pw.Scan() // a second scan must not re-emit

	shells := s.byCat(event.Category("PS08"))
	if len(shells) != 1 {
		t.Fatalf("want 1 PS08 event, got %d: %+v", len(shells), s.evs)
	}
	ev := shells[0]
	if ev.Rule == nil || ev.Rule.ID != "TEST-WEB-SHELL" || ev.Process == nil || ev.Process.PID != 701 {
		t.Fatalf("unexpected web shell event: %+v", ev)
	}
	if ev.Severity != event.High || len(ev.MITRE) != 1 || ev.MITRE[0] != "T1505.003" {
		t.Fatalf("rule level and MITRE not carried over: %+v", ev)
	}

	miners := s.byCat(event.Cryptominer)
	if len(miners) != 1 || miners[0].Rule == nil || miners[0].Rule.ID != "TEST-MINER" {
		t.Fatalf("want 1 rule-backed miner event, got %+v", miners)
	}
}
