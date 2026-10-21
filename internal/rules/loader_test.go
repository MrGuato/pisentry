package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrGuato/pisentry/internal/event"
)

// minimalRule is a valid rule used as the base for table-driven mutations.
func minimalRule() map[string]any {
	return map[string]any{
		"id":       "TEST-RULE",
		"title":    "Test rule",
		"category": "PS04",
		"level":    "high",
		"source":   "log",
		"match": map[string]any{
			"all": []any{map[string]any{"field": "log.msg", "contains": []any{"evil"}}},
		},
	}
}

func bundleJSON(t *testing.T, rules ...map[string]any) []byte {
	t.Helper()
	rs := make([]any, len(rules))
	for i, r := range rules {
		rs[i] = r
	}
	b, err := json.Marshal(map[string]any{"schema_version": 1, "rules": rs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error containing %q, got nil", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("want error containing %q, got %q", sub, err)
	}
}

func TestDefaultLoads(t *testing.T) {
	eng := Default()
	if len(eng.Rules()) == 0 {
		t.Fatal("no default rules")
	}
	cat := eng.Catalog()
	if len(cat.FIMWatches) == 0 || len(cat.ShellNames) == 0 || len(cat.GTFOSUID) == 0 ||
		len(cat.BackdoorPorts) == 0 || len(cat.StratumPorts) == 0 || len(cat.PkgManagers) == 0 ||
		len(cat.PrivGroups) == 0 {
		t.Fatalf("default catalog incomplete: %+v", cat)
	}
	for _, cr := range eng.Rules() {
		if got, ok := eng.RuleByID(cr.Rule.ID); !ok || got != cr {
			t.Errorf("RuleByID(%s) mismatch", cr.Rule.ID)
		}
		if cr.Rule.Response != "none" {
			t.Errorf("%s: response %q, want default none", cr.Rule.ID, cr.Rule.Response)
		}
		if len(cr.Rule.MITRE) == 0 {
			t.Errorf("%s: no MITRE technique", cr.Rule.ID)
		}
	}
	if _, ok := eng.RuleByID("NOPE"); ok {
		t.Error("RuleByID found a rule that does not exist")
	}
}

// The agent embeds internal/rules/default.json; deploy/rules/default.json is
// the copy that ships and gets signed (#14). They must never drift.
func TestDeployCopyMatchesEmbedded(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "rules", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	if !bytes.Equal(norm(b), norm(DefaultBytes())) {
		t.Fatal("deploy/rules/default.json differs from internal/rules/default.json; copy one over the other")
	}
}

func TestLoadBytesRejects(t *testing.T) {
	big := append([]byte(`{"schema_version":1,"rules":[]`), bytes.Repeat([]byte(" "), MaxFileSize)...)
	many := make([]map[string]any, MaxRulesPerFile+1)
	for i := range many {
		r := minimalRule()
		r["id"] = fmt.Sprintf("R%d", i)
		many[i] = r
	}
	dup := bundleJSON(t, minimalRule(), minimalRule())

	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, "empty rule file"},
		{"oversize", big, "exceeds limit"},
		{"not json", []byte("rules: []"), "invalid json"},
		{"array", []byte("[]"), "invalid json"},
		{"no version", []byte(`{"rules":[]}`), `"schema_version": required`},
		{"wrong version", []byte(`{"schema_version":2,"rules":[]}`), "want 1"},
		{"unknown top field", []byte(`{"schema_version":1,"rulez":[]}`), "unknown field"},
		{"trailing data", []byte(`{"schema_version":1,"catalog":{}} {}`), "trailing data"},
		{"nothing", []byte(`{"schema_version":1,"rules":[]}`), "no rules or catalog"},
		{"too many rules", bundleJSON(t, many...), "exceeds limit"},
		{"duplicate id", dup, "duplicate rule id"},
		{"bad backdoor port", []byte(`{"schema_version":1,"catalog":{"backdoor_ports":[{"port":0,"note":"x"}]}}`), "backdoor_ports[0]"},
		{"backdoor no note", []byte(`{"schema_version":1,"catalog":{"backdoor_ports":[{"port":22}]}}`), "backdoor_ports[0]"},
		{"bad stratum port", []byte(`{"schema_version":1,"catalog":{"stratum_ports":[70000]}}`), "stratum_ports[0]"},
		{"relative fim", []byte(`{"schema_version":1,"catalog":{"fim_watches":[{"pattern":"etc/x","category":"PS10","severity":"low"}]}}`), "must be absolute"},
		{"fim no category", []byte(`{"schema_version":1,"catalog":{"fim_watches":[{"pattern":"/etc/x","severity":"low"}]}}`), "category\": required"},
		{"unknown catalog field", []byte(`{"schema_version":1,"catalog":{"miner_names":["x"]}}`), "unknown field"},
		{"bad severity", []byte(`{"schema_version":1,"rules":[{"id":"X","title":"x","category":"PS04","level":"severe","source":"log","match":{"all":[{"field":"log.msg","equals":["a"]}]}}]}`), "unknown severity"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := LoadBytes("t.json", c.in)
			wantErr(t, err, c.want)
		})
	}
}

func TestLoadBytesUnknownNestedFields(t *testing.T) {
	r := minimalRule()
	r["severity"] = "high" // Sigma uses level, not severity
	_, _, err := LoadBytes("t.json", bundleJSON(t, r))
	wantErr(t, err, `unknown field "severity"`)

	r = minimalRule()
	r["match"] = map[string]any{"all": []any{map[string]any{"field": "log.msg", "contain": []any{"x"}}}}
	_, _, err = LoadBytes("t.json", bundleJSON(t, r))
	wantErr(t, err, `unknown field "contain"`)

	r = minimalRule()
	r["exceptions"] = []any{map[string]any{"process": "x"}}
	_, _, err = LoadBytes("t.json", bundleJSON(t, r))
	wantErr(t, err, `unknown field "process"`)
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file: want error")
	}
	_, _, err := LoadFile(dir)
	wantErr(t, err, "not a regular file")

	big := writeFile(t, dir, "big.json", bytes.Repeat([]byte(" "), MaxFileSize+1))
	_, _, err = LoadFile(big)
	wantErr(t, err, "exceeds limit")

	ok := writeFile(t, dir, "ok.json", bundleJSON(t, minimalRule()))
	b, crs, err := LoadFile(ok)
	if err != nil || b == nil || len(crs) != 1 {
		t.Fatalf("LoadFile ok: %v %v %d", err, b, len(crs))
	}
}

func TestLoadFileFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeFile(t, dir, "target", bundleJSON(t, minimalRule()))
	link := filepath.Join(dir, "rules.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, crs, err := LoadFile(link); err != nil || len(crs) != 1 {
		t.Fatalf("symlinked rule file (ConfigMap layout) rejected: %v", err)
	}
}

func TestValidatePath(t *testing.T) {
	if _, err := ValidatePath(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing path: want error")
	}

	empty := t.TempDir()
	writeFile(t, empty, "README.md", []byte("not a rule"))
	_, err := ValidatePath(empty)
	wantErr(t, err, "no .json rule files")

	dir := t.TempDir()
	a := minimalRule()
	a["id"] = "A"
	b := minimalRule()
	b["id"] = "B"
	f := writeFile(t, dir, "10-a.json", bundleJSON(t, a))
	writeFile(t, dir, "20-b.json", bundleJSON(t, b))
	writeFile(t, dir, ".hidden.json", []byte("garbage")) // dotfiles (..data) are skipped
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	eng, err := ValidatePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.Rules()) != 2 {
		t.Fatalf("got %d rules, want 2", len(eng.Rules()))
	}
	if eng, err := ValidatePath(f); err != nil || len(eng.Rules()) != 1 {
		t.Fatalf("single file: %v", err)
	}

	writeFile(t, dir, "30-dup.json", bundleJSON(t, a))
	_, err = ValidatePath(dir)
	wantErr(t, err, "already defined in")
	if !strings.Contains(err.Error(), "30-dup.json") || !strings.Contains(err.Error(), "10-a.json") {
		t.Errorf("duplicate error should name both files: %v", err)
	}

	bad := t.TempDir()
	writeFile(t, bad, "x.json", []byte("{"))
	_, err = ValidatePath(bad)
	wantErr(t, err, "x.json")
}

func TestTooManyRuleFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= MaxRuleFiles; i++ {
		writeFile(t, dir, fmt.Sprintf("%03d.json", i), []byte("{}"))
	}
	_, err := LoadOrDefault(dir)
	wantErr(t, err, "exceeds limit")
}

func TestLoadOrDefault(t *testing.T) {
	if eng, err := LoadOrDefault(""); err != nil || eng != Default() {
		t.Fatalf("empty dir setting: %v", err)
	}
	if eng, err := LoadOrDefault(filepath.Join(t.TempDir(), "missing")); err != nil || eng != Default() {
		t.Fatalf("missing dir should fall back to defaults: %v", err)
	}
	if eng, err := LoadOrDefault(t.TempDir()); err != nil || eng != Default() {
		t.Fatalf("empty dir should fall back to defaults: %v", err)
	}
	notDir := writeFile(t, t.TempDir(), "file", []byte("x"))
	if _, err := LoadOrDefault(notDir); err == nil {
		t.Error("rules.dir pointing at a file: want error")
	}

	// Override a built-in rule with an exception and a new source, add a new
	// rule, and replace one catalog list.
	base := Default()
	orig, ok := base.RuleByID("PS04-SUDO-SETCAP")
	if !ok {
		t.Fatal("PS04-SUDO-SETCAP missing from defaults")
	}
	override := minimalRule()
	override["id"] = "PS04-SUDO-SETCAP"
	override["source"] = "process"
	override["match"] = map[string]any{"all": []any{map[string]any{"field": "process.cmdline", "regex": []any{`\bsetcap\b`}}}}
	override["exceptions"] = []any{map[string]any{"parent_comm": []any{"ansible"}}}
	extra := minimalRule()
	extra["id"] = "LOCAL-1"

	dir := t.TempDir()
	b, _ := json.Marshal(map[string]any{
		"schema_version": 1,
		"catalog":        map[string]any{"shell_names": []any{"bash"}},
		"rules":          []any{override, extra},
	})
	writeFile(t, dir, "local.json", b)
	eng, err := LoadOrDefault(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.Rules()) != len(base.Rules())+1 {
		t.Fatalf("got %d rules, want %d", len(eng.Rules()), len(base.Rules())+1)
	}
	got, _ := eng.RuleByID("PS04-SUDO-SETCAP")
	if got == orig || got.Rule.Source != SourceProcess {
		t.Fatal("override did not replace the built-in rule")
	}
	if cs := eng.Catalog().ShellNames; len(cs) != 1 || cs[0] != "bash" {
		t.Fatalf("catalog override: %v", cs)
	}
	if len(eng.Catalog().FIMWatches) != len(base.Catalog().FIMWatches) {
		t.Fatal("catalog lists not in the overlay must be kept")
	}
	// The built-in engine must not have been mutated by the overlay.
	if o, _ := base.RuleByID("PS04-SUDO-SETCAP"); o != orig || len(base.Catalog().ShellNames) == 1 {
		t.Fatal("overlay mutated the embedded default engine")
	}
	// The overridden rule moved from the log index to the process index.
	in := &EvalInput{Source: SourceLog, LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "/usr/sbin/setcap cap_net_raw+ep /tmp/x"}}
	for _, r := range eng.Eval(in) {
		if r.ID == "PS04-SUDO-SETCAP" {
			t.Fatal("overridden rule still indexed under its old source")
		}
	}
	in = &EvalInput{Source: SourceProcess, Process: event.ProcessEntity{Cmdline: "setcap cap_net_raw+ep /tmp/x"}}
	if hits := eng.Eval(in); len(hits) != 1 || hits[0].ID != "PS04-SUDO-SETCAP" {
		t.Fatalf("overridden rule not under its new source: %v", hits)
	}
	in.ParentComm = "ansible"
	if hits := eng.Eval(in); len(hits) != 0 {
		t.Fatalf("exception did not suppress: %v", hits)
	}

	// A duplicate inside rules.d is an error even though overriding a
	// built-in is allowed.
	writeFile(t, dir, "local2.json", bundleJSON(t, extra))
	_, err = LoadOrDefault(dir)
	wantErr(t, err, "duplicate rule id")
}

func TestNewEngineFromBytesError(t *testing.T) {
	if _, err := NewEngineFromBytes("x.json", []byte("{")); err == nil {
		t.Fatal("want error")
	}
}
