package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/state"
)

func TestRanking(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	ev := func(c event.Category, s event.Severity, ago time.Duration) event.Event {
		return event.Event{Time: now.Add(-ago), Category: c, Severity: s, Summary: string(c)}
	}
	st := state.State{Host: "kubepi", Totals: map[event.Category]int{event.SSHBruteForce: 50}}
	// 6 high brute force (score 30) vs 1 critical reverse shell (10) vs 20 low FIM (20)
	for i := 0; i < 6; i++ {
		st.Recent = append(st.Recent, ev(event.SSHBruteForce, event.High, time.Hour))
	}
	st.Recent = append(st.Recent, ev(event.ReverseShell, event.Critical, time.Minute))
	for i := 0; i < 20; i++ {
		st.Recent = append(st.Recent, ev(event.Persistence, event.Low, time.Hour))
	}
	st.Recent = append(st.Recent, ev(event.PortScan, event.Critical, 48*time.Hour)) // outside window

	r := Build(st, 24*time.Hour, now)
	if len(r.Rows) != 10 {
		t.Fatalf("always 10 rows, got %d", len(r.Rows))
	}
	order := []event.Category{r.Rows[0].ID, r.Rows[1].ID, r.Rows[2].ID}
	want := []event.Category{event.SSHBruteForce, event.Persistence, event.ReverseShell}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("rank order %v, want %v", order, want)
		}
	}
	for _, row := range r.Rows {
		if row.ID == event.PortScan && row.Events != 0 {
			t.Errorf("event outside window counted")
		}
	}
	if r.Rows[0].AllTime != 50 || len(r.Recent) != 7 || r.Recent[0].Category != event.ReverseShell {
		t.Errorf("alltime/recent wrong: %+v", r.Recent)
	}
	var b bytes.Buffer
	r.Text(&b)
	if !strings.Contains(b.String(), "SSH brute force") || !strings.Contains(b.String(), "clean") {
		t.Errorf("text output:\n%s", b.String())
	}
}
