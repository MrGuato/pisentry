package engine

import "testing"

func TestTruncateNeutralizesEscapes(t *testing.T) {
	in := "evil\x1b[2J\x1b]0;pwned\x07‮exe.txt\x9b31m\xff"
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
