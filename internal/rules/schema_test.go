package rules

import (
	"strings"
	"testing"

	"github.com/MrGuato/pisentry/internal/event"
)

func baseRule() Rule {
	return Rule{
		ID: "T-1", Title: "t", Category: event.PrivEsc, Level: event.High, Source: SourceLog,
		Match: MatchSpec{All: []FieldCondition{{Field: "log.msg", Contains: []string{"evil"}}}},
	}
}

func mustCompile(t *testing.T, r Rule) *CompiledRule {
	t.Helper()
	cr, err := CompileRule("t.json", 0, r)
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

func TestCompileRuleRejects(t *testing.T) {
	long := strings.Repeat("a", MaxPatternLen+1)
	manyConds := make([]FieldCondition, MaxConditionsPerRule+1)
	for i := range manyConds {
		manyConds[i] = FieldCondition{Field: "log.msg", Equals: []string{"x"}}
	}
	manyPats := make([]string, MaxPatternsPerRule+1)
	for i := range manyPats {
		manyPats[i] = "p"
	}
	manyEx := make([]Exception, MaxExceptionsPerRule+1)
	for i := range manyEx {
		manyEx[i] = Exception{Comm: []string{"x"}}
	}

	cases := []struct {
		name  string
		mut   func(*Rule)
		field string
	}{
		{"no id", func(r *Rule) { r.ID = "" }, `rules[0] field "id"`},
		{"bad id", func(r *Rule) { r.ID = "has space" }, `field "id"`},
		{"long id", func(r *Rule) { r.ID = strings.Repeat("a", MaxIDLen+1) }, `field "id"`},
		{"no title", func(r *Rule) { r.Title = "" }, `field "title"`},
		{"long desc", func(r *Rule) { r.Description = strings.Repeat("a", MaxDescLen+1) }, `field "description"`},
		{"bad status", func(r *Rule) { r.Status = "beta" }, `field "status"`},
		{"no category", func(r *Rule) { r.Category = "" }, `field "category"`},
		{"bad category", func(r *Rule) { r.Category = "XX01" }, `field "category"`},
		{"category not in catalog", func(r *Rule) { r.Category = "PS99" }, `unknown category "PS99"`},
		{"bad source", func(r *Rule) { r.Source = "ebpf" }, `field "source"`},
		{"bad response", func(r *Rule) { r.Response = "reboot" }, `field "response"`},
		{"long tag", func(r *Rule) { r.Tags = []string{long} }, `field "tags"`},
		{"bad mitre", func(r *Rule) { r.MITRE = []string{"T12"} }, `field "mitre"`},
		{"no conditions", func(r *Rule) { r.Match = MatchSpec{} }, `field "match"`},
		{"too many conditions", func(r *Rule) { r.Match = MatchSpec{Any: manyConds} }, `too many conditions`},
		{"unknown field", func(r *Rule) { r.Match.All[0].Field = "process.env" }, `match.all[0].field`},
		{"no patterns", func(r *Rule) { r.Match.All[0] = FieldCondition{Field: "log.msg"} }, `has no patterns`},
		{"too many patterns", func(r *Rule) { r.Match.All[0].Contains = manyPats }, `max patterns`},
		{"empty literal", func(r *Rule) { r.Match.All[0].Contains = []string{""} }, `empty literal`},
		{"long literal", func(r *Rule) { r.Match.All[0].Contains = []string{long} }, `pattern length`},
		{"empty regex", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{""}}} }, `empty regex`},
		{"long regex", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{long}}} }, `regex length`},
		{"bad regex", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{"(a"}}} }, `invalid regex`},
		{"backreference", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{`(a)\1`}}} }, `invalid regex`},
		{"too many exceptions", func(r *Rule) { r.Exceptions = manyEx }, `too many exceptions`},
		{"empty exception", func(r *Rule) { r.Exceptions = []Exception{{}} }, `would suppress all`},
		{"exception too many values", func(r *Rule) { r.Exceptions = []Exception{{Comm: manyPats}} }, `too many values`},
		{"exception empty value", func(r *Rule) { r.Exceptions = []Exception{{Exe: []string{""}}} }, `empty value`},
		{"exception long value", func(r *Rule) { r.Exceptions = []Exception{{Paths: []string{long}}} }, `value length`},
		{"exception bad glob", func(r *Rule) { r.Exceptions = []Exception{{Paths: []string{"/etc/["}}} }, `invalid glob`},
		{"exception bad cidr", func(r *Rule) { r.Exceptions = []Exception{{CIDRs: []string{"10.0.0.0/33"}}} }, `invalid CIDR`},
		{"exception bad ip", func(r *Rule) { r.Exceptions = []Exception{{CIDRs: []string{"not-an-ip"}}} }, `invalid CIDR`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			c.mut(&r)
			_, err := CompileRule("t.json", 0, r)
			wantErr(t, err, c.field)
			if !strings.HasPrefix(err.Error(), "t.json: ") {
				t.Errorf("error must name the file: %v", err)
			}
		})
	}
}

func TestCompileRuleNormalizes(t *testing.T) {
	r := baseRule()
	r.Tags = []string{"attack.t1548.003", "attack.privilege_escalation", "ATTACK.T1059"}
	r.MITRE = []string{"T1548.003"}
	cr := mustCompile(t, r)
	if got := strings.Join(cr.Rule.MITRE, ","); got != "T1548.003,T1059" {
		t.Errorf("MITRE from tags = %q", got)
	}
	if cr.Rule.Response != "none" {
		t.Errorf("response = %q, want none", cr.Rule.Response)
	}
}

func TestMatchOperators(t *testing.T) {
	cases := []struct {
		name string
		cond FieldCondition
		val  string
		want bool
	}{
		{"equals", FieldCondition{Equals: []string{"sudo"}}, "sudo", true},
		{"equals is exact", FieldCondition{Equals: []string{"sudo"}}, "sudoedit", false},
		{"contains", FieldCondition{Contains: []string{"tcp://"}}, "stratum+tcp://pool", true},
		{"startswith", FieldCondition{StartsWith: []string{"/tmp/"}}, "/tmp/x", true},
		{"startswith miss", FieldCondition{StartsWith: []string{"/tmp/"}}, "/usr/tmp/x", false},
		{"endswith", FieldCondition{EndsWith: []string{".sh"}}, "/tmp/a.sh", true},
		{"case sensitive", FieldCondition{Contains: []string{"XMRig"}}, "xmrig", false},
		{"case insensitive literal", FieldCondition{Contains: []string{"XMRig"}, CaseInsensitive: true}, "/tmp/XMRIG", true},
		{"regex", FieldCondition{Regex: []string{`^a+b$`}}, "aaab", true},
		{"regex miss", FieldCondition{Regex: []string{`^a+b$`}}, "aaabc", false},
		{"case insensitive regex", FieldCondition{Regex: []string{`setcap`}, CaseInsensitive: true}, "SETCAP", true},
		{"ci regex already flagged", FieldCondition{Regex: []string{`(?i)setcap`}, CaseInsensitive: true}, "SetCap", true},
		{"literal or regex", FieldCondition{Equals: []string{"x"}, Regex: []string{`^y`}}, "yes", true},
		{"empty value", FieldCondition{Contains: []string{"a"}}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			c.cond.Field = "log.msg"
			r.Match = MatchSpec{All: []FieldCondition{c.cond}}
			cr := mustCompile(t, r)
			if got := cr.Match(&EvalInput{Source: SourceLog, LogMsg: c.val}); got != c.want {
				t.Errorf("Match(%q) = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestMatchAllAny(t *testing.T) {
	r := baseRule()
	r.Match = MatchSpec{
		All: []FieldCondition{{Field: "log.ident", Equals: []string{"sudo"}}},
		Any: []FieldCondition{
			{Field: "process.cmdline", Contains: []string{"setcap"}},
			{Field: "process.cmdline", Contains: []string{"chattr"}},
		},
	}
	cr := mustCompile(t, r)
	in := func(ident, cmd string) *EvalInput {
		return &EvalInput{Source: SourceLog, LogIdent: ident, Process: event.ProcessEntity{Cmdline: cmd}}
	}
	if !cr.Match(in("sudo", "chattr +i /etc/passwd")) {
		t.Error("all + one of any should match")
	}
	if cr.Match(in("su", "chattr +i /etc/passwd")) {
		t.Error("failing all must not match")
	}
	if cr.Match(in("sudo", "ls")) {
		t.Error("no any condition holding must not match")
	}
	if cr.Match(&EvalInput{Source: SourceProcess, LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "setcap"}}) {
		t.Error("wrong source must not match")
	}
	// An empty source evaluates every rule, which is what fixtures without a
	// source and `Engine.Eval` callers that do not know the source rely on.
	if !cr.Match(&EvalInput{LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "setcap"}}) {
		t.Error("empty input source should not filter")
	}
}

func TestExceptions(t *testing.T) {
	uid := func(n int) *int { return &n }
	hit := func() *EvalInput {
		return &EvalInput{
			Source:         SourceLog,
			LogMsg:         "evil",
			Process:        event.ProcessEntity{Exe: "/usr/bin/ansible-playbook", Comm: "ansible", Cmdline: "ansible-playbook site.yml", UID: uid(1000)},
			ParentComm:     "sshd",
			User:           event.UserEntity{Name: "deploy"},
			ContainerImage: "ghcr.io/acme/backup:1.2",
			Network:        event.SourceEntity{IP: "192.168.1.20"},
			File:           event.FileEntity{Path: "/etc/cron.d/backup"},
		}
	}
	cases := []struct {
		name string
		ex   Exception
		mut  func(*EvalInput)
		want bool // true = suppressed
	}{
		{"exe", Exception{Exe: []string{"/usr/bin/ansible-playbook"}}, nil, true},
		{"exe miss", Exception{Exe: []string{"/usr/bin/other"}}, nil, false},
		{"exe prefix", Exception{ExePrefix: []string{"/usr/bin/"}}, nil, true},
		{"exe prefix miss", Exception{ExePrefix: []string{"/opt/"}}, nil, false},
		{"comm", Exception{Comm: []string{"ansible"}}, nil, true},
		{"comm miss", Exception{Comm: []string{"bash"}}, nil, false},
		{"parent comm", Exception{ParentComm: []string{"sshd"}}, nil, true},
		{"parent comm miss", Exception{ParentComm: []string{"cron"}}, nil, false},
		{"process uid", Exception{UIDs: []int{1000}}, nil, true},
		{"uid miss", Exception{UIDs: []int{0}}, nil, false},
		{"user uid fallback", Exception{UIDs: []int{0}}, func(in *EvalInput) { in.Process.UID = nil; in.User.UID = uid(0) }, true},
		{"unknown uid never matches", Exception{UIDs: []int{0}}, func(in *EvalInput) { in.Process.UID = nil }, false},
		{"user", Exception{Users: []string{"deploy"}}, nil, true},
		{"user miss", Exception{Users: []string{"root"}}, nil, false},
		{"image glob", Exception{ContainerImage: []string{"ghcr.io/acme/backup:*"}}, nil, true},
		{"image exact", Exception{ContainerImage: []string{"ghcr.io/acme/backup:1.2"}}, nil, true},
		{"image miss", Exception{ContainerImage: []string{"docker.io/*"}}, nil, false},
		{"cidr", Exception{CIDRs: []string{"192.168.0.0/16"}}, nil, true},
		{"single ip", Exception{CIDRs: []string{"192.168.1.20"}}, nil, true},
		{"v4-mapped v6", Exception{CIDRs: []string{"192.168.1.0/24"}}, func(in *EvalInput) { in.Network.IP = "::ffff:192.168.1.20" }, true},
		{"cidr miss", Exception{CIDRs: []string{"10.0.0.0/8"}}, nil, false},
		{"cidr unparsable ip", Exception{CIDRs: []string{"10.0.0.0/8"}}, func(in *EvalInput) { in.Network.IP = "" }, false},
		{"path glob", Exception{Paths: []string{"/etc/cron.d/*"}}, nil, true},
		{"path miss", Exception{Paths: []string{"/etc/systemd/*"}}, nil, false},
		{"cmdline contains", Exception{CmdlineContains: []string{"site.yml"}}, nil, true},
		{"cmdline miss", Exception{CmdlineContains: []string{"other.yml"}}, nil, false},
		{"all predicates must hold", Exception{Comm: []string{"ansible"}, Users: []string{"root"}}, nil, false},
		{"all predicates hold", Exception{Comm: []string{"ansible"}, Users: []string{"deploy"}}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			r.Exceptions = []Exception{c.ex}
			cr := mustCompile(t, r)
			in := hit()
			if c.mut != nil {
				c.mut(in)
			}
			if suppressed := !cr.Match(in); suppressed != c.want {
				t.Errorf("suppressed = %v, want %v", suppressed, c.want)
			}
		})
	}

	// Multiple exceptions are ORed.
	r := baseRule()
	r.Exceptions = []Exception{{Comm: []string{"nope"}}, {Users: []string{"deploy"}}}
	if mustCompile(t, r).Match(hit()) {
		t.Error("second exception should suppress")
	}
}

// Every field a rule may name must be readable from EvalInput, or a rule on
// it would silently never match.
func TestEveryAllowedFieldIsWired(t *testing.T) {
	uid := 7
	in := &EvalInput{
		Process:        event.ProcessEntity{PID: 10, PPID: 1, UID: &uid, Comm: "c", Exe: "/e", Cmdline: "cmd"},
		ParentComm:     "pc",
		Network:        event.SourceEntity{IP: "192.0.2.1", Port: 22},
		Proto:          "tcp",
		User:           event.UserEntity{Name: "u", UID: &uid},
		File:           event.FileEntity{Path: "/p"},
		FileChange:     "modified",
		FileContent:    "content",
		Container:      event.ContainerEntity{ID: "cid", Pod: "pod", Namespace: "ns"},
		ContainerImage: "img",
		LogIdent:       "sshd",
		LogMsg:         "msg",
		K3sKind:        "Pod",
		K3sSpec:        "{}",
	}
	for f := range AllowedFields {
		if in.Field(f) == "" {
			t.Errorf("field %q is allowed in rules but EvalInput.Field returns nothing for it", f)
		}
	}
	if (&EvalInput{}).Field("process.pid") != "" || (&EvalInput{}).Field("process.ppid") != "" ||
		(&EvalInput{}).Field("process.uid") != "" || (&EvalInput{}).Field("source.port") != "" ||
		(&EvalInput{}).Field("user.uid") != "" || (&EvalInput{}).Field("bogus") != "" {
		t.Error("unset numeric fields must read as empty, not \"0\"")
	}
}

func TestEngineEval(t *testing.T) {
	var nilEng *Engine
	if nilEng.Eval(&EvalInput{}) != nil {
		t.Error("nil engine should match nothing")
	}
	in := &EvalInput{Source: SourceLog, LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "/usr/sbin/setcap cap_setuid+ep /tmp/python3"}}
	hits := Default().Eval(in)
	if len(hits) != 1 || hits[0].ID != "PS04-SUDO-SETCAP" {
		t.Fatalf("hits = %v", hits)
	}
	in.Source = ""
	if hits := Default().Eval(in); len(hits) != 1 {
		t.Fatalf("empty source should search all rules, got %v", hits)
	}
}

func TestUsesField(t *testing.T) {
	eng, err := NewEngineFromBytes("t.json", bundleJSON(t, map[string]any{
		"id": "WEB-SHELL", "title": "t", "category": "PS08", "level": "high", "source": "process",
		"match": map[string]any{
			"all": []any{map[string]any{"field": "process.comm", "equals": []any{"sh"}}},
			"any": []any{map[string]any{"field": "process.parent_comm", "equals": []any{"nginx"}}},
		},
		"exceptions": []any{map[string]any{"uids": []any{33}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !eng.UsesField(SourceProcess, "process.parent_comm") || !eng.UsesField(SourceProcess, "process.comm") {
		t.Error("match condition fields not reported")
	}
	if eng.UsesField(SourceProcess, "process.uid") {
		t.Error("exception-only field reported as a match field")
	}
	if eng.UsesField(SourceLog, "process.comm") {
		t.Error("field reported for a source with no rules")
	}
	var nilEng *Engine
	if nilEng.UsesField(SourceProcess, "process.comm") {
		t.Error("nil engine reported a field")
	}
	// ProcWatch reads uid and parent comm for every process when a rule
	// matches on them; the defaults should not force that cost.
	if Default().UsesField(SourceProcess, "process.parent_comm") || Default().UsesField(SourceProcess, "process.uid") {
		t.Error("default process rules match on parent_comm or uid")
	}
}
