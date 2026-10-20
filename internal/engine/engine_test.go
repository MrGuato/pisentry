package engine

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/metrics"
)

func TestTruncateNeutralizesEscapes(t *testing.T) {
	in := "evil\x1b[2J\x1b]0;pwned\x07\u202eexe.txt\x9b31m\xff"
	out := Truncate(in, 100)
	for _, r := range out {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e {
			t.Fatalf("control rune %U survived in %q", r, out)
		}
	}
	if got := Truncate("héllo wörld", 2); got != "h..." {
		t.Fatalf("must cut on a rune boundary, got %q", got)
	}
}

func TestEmitEnrichesSchemaV1AndSanitizesEntities(t *testing.T) {
	cfg := config.Defaults()
	eng := New(&cfg, "kubepi", nil, metrics.NewSet())
	eng.Now = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }

	var buf bytes.Buffer
	eng.AddSink(NewJSONSink(&buf))

	eng.Emit(event.Event{
		Category: event.ReverseShell,
		Severity: event.Critical,
		Detector: "proc",
		Summary:  "shell\x1b[31m alert",
		Process: &event.ProcessEntity{
			PID:     42,
			UID:     event.IntPtr(0),
			Comm:    "bash\x1b[2J",
			Exe:     "/bin/bash",
			Cmdline: "bash -i\u202e",
		},
		Source: &event.SourceEntity{IP: "203.0.113.10", Port: 4444},
		User:   &event.UserEntity{Name: "root\x07", UID: event.IntPtr(0)},
	})

	line := strings.TrimSpace(buf.String())
	if err := event.ValidateJSON([]byte(line)); err != nil {
		t.Fatalf("emitted JSON failed schema v1 validation: %v\nline: %s", err, line)
	}
	if strings.Contains(line, "\x1b") || strings.Contains(line, "\u202e") || strings.Contains(line, "\x07") {
		t.Fatalf("unsanitized control characters in output: %s", line)
	}
}
