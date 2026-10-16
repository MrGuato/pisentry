package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MrGuato/pisentry/internal/event"
)

func TestCorruptStateRecovers(t *testing.T) {
	dir := t.TempDir()
	// Simulates a Pi losing power mid-write on an older build.
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"version":1,"totals":{"PS0`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("corrupt state must not be fatal: %v", err)
	}
	if st.Recovered == "" {
		t.Fatal("expected quarantined path")
	}
	st.Record(event.Event{Category: event.PortScan})
	if err := st.Save(false); err != nil {
		t.Fatal(err)
	}
	s, err := ReadFile(filepath.Join(dir, FileName))
	if err != nil || s.Totals[event.PortScan] != 1 {
		t.Fatalf("roundtrip: %v %+v", err, s.Totals)
	}
}
