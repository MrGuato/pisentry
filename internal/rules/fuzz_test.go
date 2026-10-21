package rules

import (
	"testing"

	"github.com/MrGuato/pisentry/internal/event"
)

// FuzzLoadBytes feeds arbitrary bytes to the strict loader. The agent runs as
// root and reads rules.d, so the loader must never panic, and any bundle it
// accepts must evaluate safely against arbitrary field values.
// Run longer with: go test ./internal/rules -run '^$' -fuzz FuzzLoadBytes
func FuzzLoadBytes(f *testing.F) {
	f.Add(DefaultBytes())
	f.Add([]byte(`{"schema_version":1,"rules":[{"id":"A","title":"a","category":"PS04","level":"high","source":"log","match":{"all":[{"field":"log.msg","regex":["(a+)+$"]}]}}]}`))
	f.Add([]byte(`{"schema_version":1,"rules":[{"id":"B","title":"b","category":"PS06","level":"low","source":"process","match":{"any":[{"field":"process.comm","equals":["x"],"case_insensitive":true}]},"exceptions":[{"cidrs":["10.0.0.0/8","::1"],"paths":["/tmp/*"]}]}]}`))
	f.Add([]byte(`{"schema_version":1,"catalog":{"stratum_ports":[3333],"fim_watches":[{"pattern":"/etc/x","category":"PS10","severity":"high"}]}}`))
	f.Add([]byte(`{"schema_version":1,"rules":[]} {}`))
	f.Add([]byte(`{"schema_version":2}`))
	f.Add([]byte(`[]`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		bundle, crs, err := LoadBytes("fuzz.json", b)
		if err != nil {
			if bundle != nil || crs != nil {
				t.Fatal("error returned together with a result")
			}
			return
		}
		if len(crs) != len(bundle.Rules) {
			t.Fatalf("compiled %d of %d rules", len(crs), len(bundle.Rules))
		}
		val := string(b)
		if len(val) > 256 {
			val = val[:256]
		}
		uid := 0
		in := &EvalInput{
			Process:    event.ProcessEntity{PID: 1, UID: &uid, Comm: val, Exe: val, Cmdline: val},
			ParentComm: val,
			Network:    event.SourceEntity{IP: val},
			User:       event.UserEntity{Name: val, UID: &uid},
			File:       event.FileEntity{Path: val},
			LogIdent:   val,
			LogMsg:     val,
		}
		ids := map[string]bool{}
		for _, cr := range crs {
			if ids[cr.Rule.ID] {
				t.Fatalf("duplicate rule id %q accepted", cr.Rule.ID)
			}
			ids[cr.Rule.ID] = true
			if cr.Rule.Response == "" {
				t.Fatalf("rule %s compiled without a default response", cr.Rule.ID)
			}
			in.Source = cr.Rule.Source
			cr.Match(in)
		}
	})
}
