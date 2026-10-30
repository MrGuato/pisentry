package engine

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// Found by FuzzAuthHandle: the sudo detector keys its cooldown on the
// command line, so a forged line produced a 2 KB key with escapes and
// invalid UTF-8 that broke Event Schema v1's 512-byte limit.
func TestSanitizeEventBoundsKey(t *testing.T) {
	long := "sudo-risky|0|curl x | bash \x1b[2J\xff" + strings.Repeat("J", 4000)
	other := long[:len(long)-1] + "K"
	a := event.Event{Key: long}
	b := event.Event{Key: other}
	SanitizeEvent(&a)
	SanitizeEvent(&b)
	if len(a.Key) > maxKeyLen || len(b.Key) > maxKeyLen {
		t.Fatalf("key not bounded: %d, %d bytes", len(a.Key), len(b.Key))
	}
	if a.Key == b.Key {
		t.Fatal("two different long keys collapsed into one cooldown key")
	}
	if strings.ContainsAny(a.Key, "\x1b\xff") || !utf8.ValidString(a.Key) {
		t.Fatalf("unsanitized key: %q", a.Key)
	}
	short := event.Event{Key: "203.0.113.66"}
	SanitizeEvent(&short)
	if short.Key != "203.0.113.66" {
		t.Fatalf("short clean key changed: %q", short.Key)
	}
}
