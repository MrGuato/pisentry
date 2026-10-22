// Package rules implements Rule Schema v1, the strict JSON rule loader, and
// the compiled pattern evaluation engine.
package rules

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
)

// Hard limits enforced at load time. Inputs exceeding any limit are rejected,
// never truncated.
const (
	SchemaVersion        = 1
	MaxFileSize          = 1 << 20 // 1 MiB
	MaxRuleFiles         = 64
	MaxRulesPerFile      = 500
	MaxConditionsPerRule = 32
	MaxPatternsPerRule   = 64
	MaxPatternLen        = 512
	MaxRegexLen          = 512
	MaxExceptionsPerRule = 32
	MaxIDLen             = 128
	MaxTitleLen          = 256
	MaxDescLen           = 1024
)

var (
	reRuleID    = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	reMITRE     = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	reAttackTag = regexp.MustCompile(`^(?i)attack\.t([0-9]{4}(?:\.[0-9]{3})?)$`)
)

// Source names the telemetry stream a rule evaluates.
type Source string

const (
	SourceProcess Source = "process"
	SourceNetwork Source = "network"
	SourceFile    Source = "file"
	SourceLog     Source = "log"
	SourceK3s     Source = "k3s"
)

var validSources = map[Source]bool{
	SourceProcess: true,
	SourceNetwork: true,
	SourceFile:    true,
	SourceLog:     true,
	SourceK3s:     true,
}

var validResponses = map[string]bool{
	"":           true,
	"none":       true,
	"kill_tree":  true,
	"quarantine": true,
}

var validStatuses = map[string]bool{
	"":             true,
	"stable":       true,
	"test":         true,
	"experimental": true,
	"deprecated":   true,
}

// AllowedFields lists the Event Schema v1 fields that rules may match on.
var AllowedFields = map[string]bool{
	"process.pid":         true,
	"process.ppid":        true,
	"process.uid":         true,
	"process.comm":        true,
	"process.exe":         true,
	"process.cmdline":     true,
	"process.parent_comm": true,
	"source.ip":           true,
	"source.port":         true,
	"source.proto":        true,
	"user.name":           true,
	"user.uid":            true,
	"file.path":           true,
	"file.change":         true,
	"file.content":        true,
	"container.id":        true,
	"container.pod":       true,
	"container.namespace": true,
	"container.image":     true,
	"log.ident":           true,
	"log.msg":             true,
	"k3s.kind":            true,
	"k3s.spec":            true,
}

// Bundle is the top-level JSON structure of a rule file in /etc/pisentry/rules.d
// or deploy/rules/default.json.
type Bundle struct {
	SchemaVersion int      `json:"schema_version"`
	Catalog       *Catalog `json:"catalog,omitempty"`
	Rules         []Rule   `json:"rules"`
}

// BackdoorPort pairs a TCP/UDP port with its description.
type BackdoorPort struct {
	Port int    `json:"port"`
	Note string `json:"note"`
}

// Catalog holds the table-driven detection lists previously hardcoded in Go.
// Threshold and correlation logic stays in Go; only the data lives here.
// Miner names and stratum markers are rules (PS06-MINER-*), not catalog
// entries, so they get rule IDs, MITRE tags and per-rule exceptions.
type Catalog struct {
	StratumPorts  []int              `json:"stratum_ports,omitempty"`
	ShellNames    []string           `json:"shell_names,omitempty"`
	BackdoorPorts []BackdoorPort     `json:"backdoor_ports,omitempty"`
	FIMWatches    []config.WatchSpec `json:"fim_watches,omitempty"`
	GTFOSUID      []string           `json:"gtfo_suid,omitempty"`
	PkgManagers   []string           `json:"pkg_managers,omitempty"`
	PrivGroups    []string           `json:"priv_groups,omitempty"`
}

// Rule is a single detection rule in Rule Schema v1.
// Field names align with Sigma where applicable (id, title, status, description,
// author, references, tags, falsepositives, level).
type Rule struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	Status         string         `json:"status,omitempty"`
	Description    string         `json:"description,omitempty"`
	Author         string         `json:"author,omitempty"`
	References     []string       `json:"references,omitempty"`
	Category       event.Category `json:"category"`
	Level          event.Severity `json:"level"`
	MITRE          []string       `json:"mitre,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	Source         Source         `json:"source"`
	Match          MatchSpec      `json:"match"`
	Exceptions     []Exception    `json:"exceptions,omitempty"`
	FalsePositives []string       `json:"falsepositives,omitempty"`
	Response       string         `json:"response,omitempty"`
}

// MatchSpec combines field conditions. If both All and Any are non-empty,
// every condition in All must hold AND at least one condition in Any must hold.
type MatchSpec struct {
	All []FieldCondition `json:"all,omitempty"`
	Any []FieldCondition `json:"any,omitempty"`
}

// FieldCondition tests one named field. Literal operators (Equals, Contains,
// StartsWith, EndsWith) are kept separate from Regex so a literal prefilter can
// inspect them without parsing regular expressions. Within one FieldCondition,
// matching any listed pattern satisfies the condition.
type FieldCondition struct {
	Field           string   `json:"field"`
	Equals          []string `json:"equals,omitempty"`
	Contains        []string `json:"contains,omitempty"`
	StartsWith      []string `json:"startswith,omitempty"`
	EndsWith        []string `json:"endswith,omitempty"`
	Regex           []string `json:"regex,omitempty"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty"`
}

// Exception suppresses a rule match when all non-empty predicates in the
// Exception match the input. Multiple Exceptions on a Rule are ORed together.
type Exception struct {
	Exe             []string `json:"exe,omitempty"`
	ExePrefix       []string `json:"exe_prefix,omitempty"`
	Comm            []string `json:"comm,omitempty"`
	ParentComm      []string `json:"parent_comm,omitempty"`
	UIDs            []int    `json:"uids,omitempty"`
	Users           []string `json:"users,omitempty"`
	ContainerImage  []string `json:"container_image,omitempty"`
	CIDRs           []string `json:"cidrs,omitempty"`
	Paths           []string `json:"paths,omitempty"`
	CmdlineContains []string `json:"cmdline_contains,omitempty"`
}

// Matcher evaluates a compiled condition against a single field value.
// Literal and regex matchers are distinct implementations behind this interface.
type Matcher interface {
	MatchValue(val string) bool
}

type literalMatcher struct {
	ci         bool
	equals     []string
	contains   []string
	startsWith []string
	endsWith   []string
}

func newLiteralMatcher(c FieldCondition) *literalMatcher {
	norm := func(in []string) []string {
		if len(in) == 0 {
			return nil
		}
		out := make([]string, len(in))
		for i, s := range in {
			if c.CaseInsensitive {
				out[i] = strings.ToLower(s)
			} else {
				out[i] = s
			}
		}
		return out
	}
	return &literalMatcher{
		ci:         c.CaseInsensitive,
		equals:     norm(c.Equals),
		contains:   norm(c.Contains),
		startsWith: norm(c.StartsWith),
		endsWith:   norm(c.EndsWith),
	}
}

func (m *literalMatcher) empty() bool {
	return len(m.equals) == 0 && len(m.contains) == 0 && len(m.startsWith) == 0 && len(m.endsWith) == 0
}

func (m *literalMatcher) MatchValue(val string) bool {
	if m.ci {
		val = strings.ToLower(val)
	}
	for _, p := range m.equals {
		if val == p {
			return true
		}
	}
	for _, p := range m.contains {
		if strings.Contains(val, p) {
			return true
		}
	}
	for _, p := range m.startsWith {
		if strings.HasPrefix(val, p) {
			return true
		}
	}
	for _, p := range m.endsWith {
		if strings.HasSuffix(val, p) {
			return true
		}
	}
	return false
}

type regexMatcher struct {
	res []*regexp.Regexp
}

func (m *regexMatcher) MatchValue(val string) bool {
	for _, re := range m.res {
		if re.MatchString(val) {
			return true
		}
	}
	return false
}

type compiledCondition struct {
	field    string
	matchers []Matcher
}

func (cc compiledCondition) eval(in *EvalInput) bool {
	val := in.Field(cc.field)
	for _, m := range cc.matchers {
		if m.MatchValue(val) {
			return true
		}
	}
	return false
}

type compiledException struct {
	raw      Exception
	prefixes []netip.Prefix
}

func (ce compiledException) matches(in *EvalInput) bool {
	r := ce.raw
	if len(r.Exe) > 0 && !sliceContains(r.Exe, in.Process.Exe) {
		return false
	}
	if len(r.ExePrefix) > 0 && !hasAnyPrefix(in.Process.Exe, r.ExePrefix) {
		return false
	}
	if len(r.Comm) > 0 && !sliceContains(r.Comm, in.Process.Comm) {
		return false
	}
	if len(r.ParentComm) > 0 && !sliceContains(r.ParentComm, in.ParentComm) {
		return false
	}
	if len(r.UIDs) > 0 {
		uid := in.effectiveUID()
		if uid < 0 || !intSliceContains(r.UIDs, uid) {
			return false
		}
	}
	if len(r.Users) > 0 && !sliceContains(r.Users, in.User.Name) {
		return false
	}
	if len(r.ContainerImage) > 0 && !globMatchAny(r.ContainerImage, in.ContainerImage) {
		return false
	}
	if len(ce.prefixes) > 0 && !ipInPrefixes(in.Network.IP, ce.prefixes) {
		return false
	}
	if len(r.Paths) > 0 && !globMatchAny(r.Paths, in.File.Path) {
		return false
	}
	if len(r.CmdlineContains) > 0 && !containsAnySubstr(in.Process.Cmdline, r.CmdlineContains) {
		return false
	}
	return true
}

// CompiledRule is a validated, pre-compiled Rule ready for lock-free evaluation.
type CompiledRule struct {
	Rule       Rule
	all        []compiledCondition
	any        []compiledCondition
	exceptions []compiledException
}

// EvalInput represents a normalized telemetry record against which rules run.
// It uses Event Schema v1 entity structures directly so fixtures (#31) and
// live detectors share the exact same field model.
type EvalInput struct {
	Source         Source                `json:"source"`
	Process        event.ProcessEntity   `json:"process,omitempty"`
	ParentComm     string                `json:"parent_comm,omitempty"`
	Network        event.SourceEntity    `json:"network,omitempty"`
	Proto          string                `json:"proto,omitempty"`
	User           event.UserEntity      `json:"user,omitempty"`
	File           event.FileEntity      `json:"file,omitempty"`
	FileChange     string                `json:"file_change,omitempty"`
	FileContent    string                `json:"file_content,omitempty"`
	Container      event.ContainerEntity `json:"container,omitempty"`
	ContainerImage string                `json:"container_image,omitempty"`
	LogIdent       string                `json:"log_ident,omitempty"`
	LogMsg         string                `json:"log_msg,omitempty"`
	K3sKind        string                `json:"k3s_kind,omitempty"`
	K3sSpec        string                `json:"k3s_spec,omitempty"`
}

func (in *EvalInput) effectiveUID() int {
	if in.Process.UID != nil {
		return *in.Process.UID
	}
	if in.User.UID != nil {
		return *in.User.UID
	}
	return -1
}

// Field extracts a named Event Schema v1 field from EvalInput.
func (in *EvalInput) Field(name string) string {
	switch name {
	case "process.pid":
		if in.Process.PID == 0 {
			return ""
		}
		return strconv.Itoa(in.Process.PID)
	case "process.ppid":
		if in.Process.PPID == 0 {
			return ""
		}
		return strconv.Itoa(in.Process.PPID)
	case "process.uid":
		if in.Process.UID == nil {
			return ""
		}
		return strconv.Itoa(*in.Process.UID)
	case "process.comm":
		return in.Process.Comm
	case "process.exe":
		return in.Process.Exe
	case "process.cmdline":
		return in.Process.Cmdline
	case "process.parent_comm":
		return in.ParentComm
	case "source.ip":
		return in.Network.IP
	case "source.port":
		if in.Network.Port == 0 {
			return ""
		}
		return strconv.Itoa(in.Network.Port)
	case "source.proto":
		return in.Proto
	case "user.name":
		return in.User.Name
	case "user.uid":
		if in.User.UID == nil {
			return ""
		}
		return strconv.Itoa(*in.User.UID)
	case "file.path":
		return in.File.Path
	case "file.change":
		return in.FileChange
	case "file.content":
		return in.FileContent
	case "container.id":
		return in.Container.ID
	case "container.pod":
		return in.Container.Pod
	case "container.namespace":
		return in.Container.Namespace
	case "container.image":
		return in.ContainerImage
	case "log.ident":
		return in.LogIdent
	case "log.msg":
		return in.LogMsg
	case "k3s.kind":
		return in.K3sKind
	case "k3s.spec":
		return in.K3sSpec
	}
	return ""
}

// Match evaluates cr against in and reports whether it matched (and was not exempted).
func (cr *CompiledRule) Match(in *EvalInput) bool {
	if in.Source != "" && cr.Rule.Source != in.Source {
		return false
	}
	for _, c := range cr.all {
		if !c.eval(in) {
			return false
		}
	}
	if len(cr.any) > 0 {
		hit := false
		for _, c := range cr.any {
			if c.eval(in) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, ex := range cr.exceptions {
		if ex.matches(in) {
			return false
		}
	}
	return true
}

// Engine holds a compiled, immutable set of rules and catalog data.
type Engine struct {
	catalog Catalog
	rules   []*CompiledRule
	byID    map[string]*CompiledRule
	bySrc   map[Source][]*CompiledRule
}

// Catalog returns the merged table-driven catalog.
func (e *Engine) Catalog() Catalog { return e.catalog }

// Rules returns all compiled rules in deterministic order.
func (e *Engine) Rules() []*CompiledRule { return e.rules }

// RuleByID looks up a compiled rule by ID.
func (e *Engine) RuleByID(id string) (*CompiledRule, bool) {
	r, ok := e.byID[id]
	return r, ok
}

// UsesField reports whether any rule for src has a match condition on field.
// Detectors use it to skip costly lookups no rule needs. Exceptions are not
// counted: they can only suppress a match, so a lookup can wait for a hit.
func (e *Engine) UsesField(src Source, field string) bool {
	if e == nil {
		return false
	}
	for _, cr := range e.bySrc[src] {
		for _, conds := range [][]compiledCondition{cr.all, cr.any} {
			for _, c := range conds {
				if c.field == field {
					return true
				}
			}
		}
	}
	return false
}

// Eval returns every rule for in.Source that matches in.
func (e *Engine) Eval(in *EvalInput) []Rule {
	if e == nil {
		return nil
	}
	candidates := e.rules
	if in.Source != "" {
		candidates = e.bySrc[in.Source]
	}
	var out []Rule
	for _, cr := range candidates {
		if cr.Match(in) {
			out = append(out, cr.Rule)
		}
	}
	return out
}

// CompileRule validates and compiles a single Rule, prefixing any error with file.
func CompileRule(file string, idx int, r Rule) (*CompiledRule, error) {
	errf := func(field, msg string, args ...any) error {
		id := r.ID
		if id == "" {
			id = fmt.Sprintf("rules[%d]", idx)
		}
		return fmt.Errorf("%s: rule %s field %q: %s", file, id, field, fmt.Sprintf(msg, args...))
	}

	if r.ID == "" {
		return nil, errf("id", "required")
	}
	if len(r.ID) > MaxIDLen || !reRuleID.MatchString(r.ID) {
		return nil, errf("id", "invalid rule id %q", r.ID)
	}
	if r.Title == "" || len(r.Title) > MaxTitleLen {
		return nil, errf("title", "must be 1..%d bytes", MaxTitleLen)
	}
	if len(r.Description) > MaxDescLen {
		return nil, errf("description", "exceeds max length %d", MaxDescLen)
	}
	if !validStatuses[r.Status] {
		return nil, errf("status", "unknown status %q", r.Status)
	}
	if !knownCategory(r.Category) {
		return nil, errf("category", "unknown category %q, see `pisentry categories`", r.Category)
	}
	if !validSources[r.Source] {
		return nil, errf("source", "must be process, network, file, log or k3s (got %q)", r.Source)
	}
	if !validResponses[r.Response] {
		return nil, errf("response", "invalid response %q", r.Response)
	}
	if r.Response == "" {
		r.Response = "none"
	}

	// Extract MITRE IDs from Sigma-style tags ("attack.t1059.004") if present.
	for _, tag := range r.Tags {
		if len(tag) > MaxIDLen {
			return nil, errf("tags", "tag exceeds max length %d", MaxIDLen)
		}
		if m := reAttackTag.FindStringSubmatch(tag); m != nil {
			tid := "T" + strings.ToUpper(m[1])
			if !sliceContains(r.MITRE, tid) {
				r.MITRE = append(r.MITRE, tid)
			}
		}
	}
	for _, m := range r.MITRE {
		if !reMITRE.MatchString(m) {
			return nil, errf("mitre", "invalid MITRE technique ID %q", m)
		}
	}

	totalConds := len(r.Match.All) + len(r.Match.Any)
	if totalConds == 0 {
		return nil, errf("match", "must specify at least one condition in 'all' or 'any'")
	}
	if totalConds > MaxConditionsPerRule {
		return nil, errf("match", "too many conditions (%d > %d)", totalConds, MaxConditionsPerRule)
	}

	totalPatterns := 0
	compileConds := func(branch string, cs []FieldCondition) ([]compiledCondition, error) {
		out := make([]compiledCondition, 0, len(cs))
		for i, c := range cs {
			fref := fmt.Sprintf("match.%s[%d]", branch, i)
			if !AllowedFields[c.Field] {
				return nil, errf(fref+".field", "unknown field %q", c.Field)
			}
			nLit := len(c.Equals) + len(c.Contains) + len(c.StartsWith) + len(c.EndsWith)
			nReg := len(c.Regex)
			if nLit+nReg == 0 {
				return nil, errf(fref, "condition on %q has no patterns", c.Field)
			}
			totalPatterns += nLit + nReg
			if totalPatterns > MaxPatternsPerRule {
				return nil, errf(fref, "rule exceeds max patterns (%d > %d)", totalPatterns, MaxPatternsPerRule)
			}
			for _, list := range [][]string{c.Equals, c.Contains, c.StartsWith, c.EndsWith} {
				for _, p := range list {
					if p == "" {
						return nil, errf(fref, "empty literal pattern")
					}
					if len(p) > MaxPatternLen {
						return nil, errf(fref, "pattern length %d exceeds %d", len(p), MaxPatternLen)
					}
				}
			}
			var ms []Matcher
			if lm := newLiteralMatcher(c); !lm.empty() {
				ms = append(ms, lm)
			}
			if nReg > 0 {
				rm := &regexMatcher{res: make([]*regexp.Regexp, 0, nReg)}
				for _, expr := range c.Regex {
					if expr == "" {
						return nil, errf(fref+".regex", "empty regex")
					}
					if len(expr) > MaxRegexLen {
						return nil, errf(fref+".regex", "regex length %d exceeds %d", len(expr), MaxRegexLen)
					}
					pat := expr
					if c.CaseInsensitive && !strings.HasPrefix(pat, "(?i)") {
						pat = "(?i)" + pat
					}
					re, err := regexp.Compile(pat)
					if err != nil {
						return nil, errf(fref+".regex", "invalid regex %q: %v", expr, err)
					}
					rm.res = append(rm.res, re)
				}
				ms = append(ms, rm)
			}
			out = append(out, compiledCondition{field: c.Field, matchers: ms})
		}
		return out, nil
	}

	allConds, err := compileConds("all", r.Match.All)
	if err != nil {
		return nil, err
	}
	anyConds, err := compileConds("any", r.Match.Any)
	if err != nil {
		return nil, err
	}

	if len(r.Exceptions) > MaxExceptionsPerRule {
		return nil, errf("exceptions", "too many exceptions (%d > %d)", len(r.Exceptions), MaxExceptionsPerRule)
	}
	exList := make([]compiledException, 0, len(r.Exceptions))
	for i, ex := range r.Exceptions {
		fref := fmt.Sprintf("exceptions[%d]", i)
		nVals := len(ex.Exe) + len(ex.ExePrefix) + len(ex.Comm) + len(ex.ParentComm) +
			len(ex.UIDs) + len(ex.Users) + len(ex.ContainerImage) +
			len(ex.CIDRs) + len(ex.Paths) + len(ex.CmdlineContains)
		if nVals == 0 {
			return nil, errf(fref, "empty exception would suppress all matches")
		}
		if nVals > MaxPatternsPerRule {
			return nil, errf(fref, "too many values (%d > %d)", nVals, MaxPatternsPerRule)
		}
		for _, list := range [][]string{ex.Exe, ex.ExePrefix, ex.Comm, ex.ParentComm, ex.Users,
			ex.ContainerImage, ex.CIDRs, ex.Paths, ex.CmdlineContains} {
			for _, v := range list {
				if v == "" {
					return nil, errf(fref, "empty value")
				}
				if len(v) > MaxPatternLen {
					return nil, errf(fref, "value length %d exceeds %d", len(v), MaxPatternLen)
				}
			}
		}
		for _, p := range append(append([]string(nil), ex.ContainerImage...), ex.Paths...) {
			if _, err := filepath.Match(p, ""); err != nil {
				return nil, errf(fref, "invalid glob %q: %v", p, err)
			}
		}
		var prefixes []netip.Prefix
		for _, cidr := range ex.CIDRs {
			p, err := parseCIDR(cidr)
			if err != nil {
				return nil, errf(fref+".cidrs", "invalid CIDR or IP %q: %v", cidr, err)
			}
			prefixes = append(prefixes, p)
		}
		exList = append(exList, compiledException{raw: ex, prefixes: prefixes})
	}

	return &CompiledRule{
		Rule:       r,
		all:        allConds,
		any:        anyConds,
		exceptions: exList,
	}, nil
}

func knownCategory(c event.Category) bool {
	for _, ci := range event.Catalog {
		if ci.ID == c {
			return true
		}
	}
	return false
}

func parseCIDR(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func ipInPrefixes(ip string, ps []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func sliceContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func intSliceContains(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsAnySubstr(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func globMatchAny(patterns []string, val string) bool {
	for _, p := range patterns {
		if p == val {
			return true
		}
		if ok, _ := filepath.Match(p, val); ok {
			return true
		}
	}
	return false
}
