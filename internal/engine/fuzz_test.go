package engine

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzTruncate checks the properties every untrusted string relies on
// before it reaches JSON, a webhook or a terminal: valid UTF-8, no C0 or C1
// controls, no DEL, no bidi overrides or isolates, and never longer than the
// cap plus the "..." marker (Event Schema v1 limits are cap+3 for this).
func FuzzTruncate(f *testing.F) {
	f.Add("evil\x1b[2J\x1b]0;pwned\x07‮exe.txt\x9b31m\xff", 100)
	f.Add("héllo wörld", 2)
	f.Add("⁦isolate⁩‎‏", 4)
	f.Add("\xc2\x9b\xe2\x80\xae", 1)
	f.Add(strings.Repeat("界", 200), 400)
	f.Add("", 0)
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n < 0 || n > 1<<16 {
			return // callers pass small positive constants
		}
		out := Truncate(s, n)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 out of %q: %q", s, out)
		}
		for _, r := range out {
			switch {
			case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
				t.Fatalf("control %U survived: %q", r, out)
			case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
				t.Fatalf("bidi control %U survived: %q", r, out)
			}
		}
		if len(out) > n+len("...") {
			t.Fatalf("len %d exceeds cap %d+3: %q", len(out), n, out)
		}
		if Truncate(out, n+len("...")) != out {
			t.Fatalf("not idempotent: %q", out)
		}
	})
}
