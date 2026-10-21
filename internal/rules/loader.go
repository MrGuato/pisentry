package rules

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/MrGuato/pisentry/internal/config"
)

//go:embed default.json
var defaultBundleJSON []byte

var (
	defaultOnce sync.Once
	defaultEng  *Engine
)

// Default returns the compiled built-in rule and catalog engine from default.json.
func Default() *Engine {
	defaultOnce.Do(func() {
		eng, err := NewEngineFromBytes("embedded/default.json", defaultBundleJSON)
		if err != nil {
			panic("invalid embedded default.json: " + err.Error())
		}
		defaultEng = eng
	})
	return defaultEng
}

// DefaultBytes returns the raw embedded default.json bytes (used by tests to
// ensure deploy/rules/default.json and internal/rules/default.json stay identical).
func DefaultBytes() []byte { return defaultBundleJSON }

// NewEngineFromBytes parses and compiles a single JSON rule bundle.
func NewEngineFromBytes(name string, b []byte) (*Engine, error) {
	bundle, crs, err := LoadBytes(name, b)
	if err != nil {
		return nil, err
	}
	eng := newEmptyEngine()
	if bundle.Catalog != nil {
		mergeCatalog(&eng.catalog, bundle.Catalog)
	}
	for _, cr := range crs {
		eng.addRule(cr)
	}
	return eng, nil
}

func newEmptyEngine() *Engine {
	return &Engine{
		byID:  map[string]*CompiledRule{},
		bySrc: map[Source][]*CompiledRule{},
	}
}

// addRule adds cr, or replaces the rule with the same ID in place so rule
// order stays stable. The source index is rebuilt because an override may
// change the rule's source.
func (e *Engine) addRule(cr *CompiledRule) {
	if _, exists := e.byID[cr.Rule.ID]; exists {
		for i, old := range e.rules {
			if old.Rule.ID == cr.Rule.ID {
				e.rules[i] = cr
				break
			}
		}
		e.bySrc = map[Source][]*CompiledRule{}
		for _, r := range e.rules {
			e.bySrc[r.Rule.Source] = append(e.bySrc[r.Rule.Source], r)
		}
	} else {
		e.rules = append(e.rules, cr)
		e.bySrc[cr.Rule.Source] = append(e.bySrc[cr.Rule.Source], cr)
	}
	e.byID[cr.Rule.ID] = cr
}

func mergeCatalog(dst *Catalog, src *Catalog) {
	if len(src.StratumPorts) > 0 {
		dst.StratumPorts = append([]int(nil), src.StratumPorts...)
	}
	if len(src.ShellNames) > 0 {
		dst.ShellNames = append([]string(nil), src.ShellNames...)
	}
	if len(src.BackdoorPorts) > 0 {
		dst.BackdoorPorts = append([]BackdoorPort(nil), src.BackdoorPorts...)
	}
	if len(src.FIMWatches) > 0 {
		dst.FIMWatches = append([]config.WatchSpec(nil), src.FIMWatches...)
	}
	if len(src.GTFOSUID) > 0 {
		dst.GTFOSUID = append([]string(nil), src.GTFOSUID...)
	}
	if len(src.PkgManagers) > 0 {
		dst.PkgManagers = append([]string(nil), src.PkgManagers...)
	}
	if len(src.PrivGroups) > 0 {
		dst.PrivGroups = append([]string(nil), src.PrivGroups...)
	}
}

// LoadBytes strictly parses and validates one JSON rule bundle buffer.
func LoadBytes(name string, b []byte) (*Bundle, []*CompiledRule, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("%s: empty rule file", name)
	}
	if len(b) > MaxFileSize {
		return nil, nil, fmt.Errorf("%s: file size %d exceeds limit %d", name, len(b), MaxFileSize)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var bundle Bundle
	if err := dec.Decode(&bundle); err != nil {
		return nil, nil, fmt.Errorf("%s: invalid json: %w", name, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, nil, fmt.Errorf("%s: unexpected trailing data after top-level JSON object", name)
	}

	if bundle.SchemaVersion == 0 {
		return nil, nil, fmt.Errorf("%s: field \"schema_version\": required", name)
	}
	if bundle.SchemaVersion != SchemaVersion {
		return nil, nil, fmt.Errorf("%s: field \"schema_version\": got %d, want %d", name, bundle.SchemaVersion, SchemaVersion)
	}
	if len(bundle.Rules) > MaxRulesPerFile {
		return nil, nil, fmt.Errorf("%s: field \"rules\": count %d exceeds limit %d", name, len(bundle.Rules), MaxRulesPerFile)
	}
	if bundle.Catalog == nil && len(bundle.Rules) == 0 {
		return nil, nil, fmt.Errorf("%s: field \"rules\": bundle contains no rules or catalog", name)
	}
	if bundle.Catalog != nil {
		if err := validateCatalog(name, bundle.Catalog); err != nil {
			return nil, nil, err
		}
	}

	seen := make(map[string]bool, len(bundle.Rules))
	compiled := make([]*CompiledRule, 0, len(bundle.Rules))
	for i, r := range bundle.Rules {
		cr, err := CompileRule(name, i, r)
		if err != nil {
			return nil, nil, err
		}
		if seen[cr.Rule.ID] {
			return nil, nil, fmt.Errorf("%s: rule %s field \"id\": duplicate rule id", name, cr.Rule.ID)
		}
		seen[cr.Rule.ID] = true
		compiled = append(compiled, cr)
	}
	return &bundle, compiled, nil
}

func validateCatalog(name string, c *Catalog) error {
	for i, bp := range c.BackdoorPorts {
		if bp.Port < 1 || bp.Port > 65535 || bp.Note == "" {
			return fmt.Errorf("%s: field \"catalog.backdoor_ports[%d]\": invalid port %d or empty note", name, i, bp.Port)
		}
	}
	for i, p := range c.StratumPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s: field \"catalog.stratum_ports[%d]\": invalid port %d", name, i, p)
		}
	}
	for i, w := range c.FIMWatches {
		if w.Pattern == "" || !strings.HasPrefix(w.Pattern, "/") {
			return fmt.Errorf("%s: field \"catalog.fim_watches[%d].pattern\": must be absolute path", name, i)
		}
		if w.Category == "" {
			return fmt.Errorf("%s: field \"catalog.fim_watches[%d].category\": required", name, i)
		}
	}
	return nil
}

// LoadFile reads a regular file with a hard size limit and validates it.
// Symlinks are followed, because Kubernetes mounts ConfigMap keys as symlinks
// into a ..data directory, but the target must be a regular file.
func LoadFile(path string) (*Bundle, []*CompiledRule, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > MaxFileSize {
		return nil, nil, fmt.Errorf("%s: file size %d exceeds limit %d", path, fi.Size(), MaxFileSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return LoadBytes(path, b)
}

// ruleFiles lists the *.json files in dir in lexical order. Dotfiles are
// skipped, which also skips the ..data entries of a Kubernetes ConfigMap mount.
func ruleFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	if len(files) > MaxRuleFiles {
		return nil, fmt.Errorf("%s: %d rule files exceeds limit %d", dir, len(files), MaxRuleFiles)
	}
	sort.Strings(files)
	return files, nil
}

// overlay loads files in order on top of eng. Duplicate rule IDs between the
// files are rejected with an error naming both files.
func overlay(eng *Engine, files []string) error {
	definedIn := map[string]string{}
	for _, f := range files {
		bundle, crs, err := LoadFile(f)
		if err != nil {
			return err
		}
		if bundle.Catalog != nil {
			mergeCatalog(&eng.catalog, bundle.Catalog)
		}
		for _, cr := range crs {
			if prev, dup := definedIn[cr.Rule.ID]; dup {
				return fmt.Errorf("%s: rule %s field \"id\": duplicate rule id (already defined in %s)", f, cr.Rule.ID, prev)
			}
			definedIn[cr.Rule.ID] = f
			eng.addRule(cr)
		}
	}
	return nil
}

// ValidatePath validates a rule file or every *.json file in a directory on
// its own, without the embedded defaults. Used by `pisentry check -rules`.
func ValidatePath(path string) (*Engine, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if fi.IsDir() {
		if files, err = ruleFiles(path); err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s: no .json rule files found", path)
		}
	}
	eng := newEmptyEngine()
	if err := overlay(eng, files); err != nil {
		return nil, err
	}
	return eng, nil
}

// LoadOrDefault starts with the embedded Default() rules and catalog, then
// overlays any *.json files found in dir (if dir exists and is non-empty).
// Duplicate rule IDs across files inside dir are rejected; a rule in dir with
// the same ID as an embedded default rule replaces the embedded rule, which is
// how a user adds exceptions to a built-in rule. A catalog list in dir
// replaces the built-in list of the same name.
func LoadOrDefault(dir string) (*Engine, error) {
	base := Default()
	if dir == "" {
		return base, nil
	}
	files, err := ruleFiles(dir)
	if errors.Is(err, os.ErrNotExist) {
		return base, nil
	}
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return base, nil
	}
	eng := newEmptyEngine()
	mergeCatalog(&eng.catalog, &base.catalog)
	for _, cr := range base.rules {
		eng.addRule(cr)
	}
	if err := overlay(eng, files); err != nil {
		return nil, err
	}
	return eng, nil
}
