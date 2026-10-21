package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fixtureRoot holds the per-rule fixtures (#31):
//
//	testdata/rules/<rule-id>/positive/*.json  inputs the rule must fire on
//	testdata/rules/<rule-id>/negative/*.json  inputs the rule must stay quiet on
//
// Each file is one EvalInput, the same normalized record the detectors build,
// so a fixture replays with no root, no /proc and no network.
const fixtureRoot = "testdata/rules"

// loadFixture strictly decodes one fixture. Unknown fields are rejected so a
// typo in a field name cannot turn a positive fixture into a silent no-op.
func loadFixture(path string) (*EvalInput, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var in EvalInput
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%s: trailing data after fixture", path)
	}
	return &in, nil
}

func fixtureFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

// replayFixtures checks every rule in eng against its fixtures under root.
// Rule packs (#15) reuse it with their own engine and fixture tree.
func replayFixtures(t *testing.T, eng *Engine, root string) {
	t.Helper()
	for _, cr := range eng.Rules() {
		id := cr.Rule.ID
		t.Run(id, func(t *testing.T) {
			for _, kind := range []string{"positive", "negative"} {
				files := fixtureFiles(t, filepath.Join(root, id, kind))
				if len(files) == 0 {
					t.Errorf("no %s fixture: add %s/%s/%s/<name>.json", kind, root, id, kind)
					continue
				}
				for _, f := range files {
					in, err := loadFixture(f)
					if err != nil {
						t.Error(err)
						continue
					}
					if in.Source == "" {
						in.Source = cr.Rule.Source
					}
					if in.Source != cr.Rule.Source {
						t.Errorf("%s: source %q, rule evaluates %q", f, in.Source, cr.Rule.Source)
						continue
					}
					fired := false
					for _, hit := range eng.Eval(in) {
						fired = fired || hit.ID == id
					}
					switch {
					case kind == "positive" && !fired:
						t.Errorf("%s: rule did not fire", f)
					case kind == "negative" && fired:
						t.Errorf("%s: rule fired on benign input", f)
					}
				}
			}
		})
	}

	// A fixture directory with no rule is a renamed or deleted rule whose
	// tests no longer run.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, ok := eng.RuleByID(e.Name()); !ok {
			t.Errorf("%s/%s: fixtures for a rule that does not exist", root, e.Name())
		}
	}
}

func TestDefaultRuleFixtures(t *testing.T) {
	replayFixtures(t, Default(), fixtureRoot)
}

func TestLoadFixtureRejects(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown.json":  `{"source":"log","log_mesage":"typo"}`,
		"trailing.json": `{"source":"log"} {}`,
		"badjson.json":  `{"source":`,
	} {
		p := writeFile(t, dir, name, []byte(body))
		if _, err := loadFixture(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := loadFixture(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "missing.json") {
		t.Errorf("missing file: %v", err)
	}
}
