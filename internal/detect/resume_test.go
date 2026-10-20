package detect

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MrGuato/pisentry/internal/state"
)

func TestResumeDelay(t *testing.T) {
	d, _, c := newDeps(t, nil)
	hour := time.Hour
	set := func(last time.Time) {
		d.Store.Update(func(s *state.State) { s.Baselines.LastRun["suid"] = last })
	}
	if w, _ := d.resumeDelay("suid", hour); w != 0 {
		t.Fatalf("no saved run must mean run now, got %v", w)
	}
	set(c.t.Add(-10 * time.Minute))
	if w, _ := d.resumeDelay("suid", hour); w != 50*time.Minute {
		t.Fatalf("want 50m left, got %v", w)
	}
	set(c.t.Add(-2 * hour))
	if w, _ := d.resumeDelay("suid", hour); w != 0 {
		t.Fatalf("overdue scan must run now, got %v", w)
	}
	set(c.t.Add(time.Minute))
	if w, _ := d.resumeDelay("suid", hour); w != 0 {
		t.Fatalf("saved time in the future must run now, got %v", w)
	}
	set(c.t.Add(-time.Second))
	if w, _ := d.resumeDelay("suid", resumeMin-time.Second); w != 0 {
		t.Fatalf("fast schedules never wait, got %v", w)
	}
}

// loopOnce runs Loop until it has had a moment to make its first run.
func loopOnce(d Deps, name string, interval time.Duration) int32 {
	var n atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	Loop(ctx, d, name, interval, func() error { n.Add(1); return nil })
	return n.Load()
}

func TestLoopWaitsOutRecentScan(t *testing.T) {
	d, _, c := newDeps(t, nil)
	d.Store.Update(func(s *state.State) { s.Baselines.LastRun["suid"] = c.t.Add(-time.Minute) })
	if n := loopOnce(d, "suid", 6*time.Hour); n != 0 {
		t.Fatalf("a scan one minute old must not repeat on start, ran %d times", n)
	}
}

func TestLoopRunsAndRecordsOverdueScan(t *testing.T) {
	d, _, c := newDeps(t, nil)
	d.Store.Update(func(s *state.State) { s.Baselines.LastRun["suid"] = c.t.Add(-7 * time.Hour) })
	if n := loopOnce(d, "suid", 6*time.Hour); n != 1 {
		t.Fatalf("overdue scan must run once on start, ran %d times", n)
	}
	var last time.Time
	d.Store.View(func(s *state.State) { last = s.Baselines.LastRun["suid"] })
	if !last.Equal(c.t) {
		t.Fatalf("run time not recorded: %v", last)
	}
}

func TestLoopFastScheduleNotPersisted(t *testing.T) {
	d, _, _ := newDeps(t, nil)
	if n := loopOnce(d, "proc", 15*time.Second); n != 1 {
		t.Fatalf("fast detector must run on start, ran %d times", n)
	}
	d.Store.View(func(s *state.State) {
		if _, ok := s.Baselines.LastRun["proc"]; ok {
			t.Fatal("fast detector run time must not be saved")
		}
	})
}

func TestResetBaselinesForcesRescan(t *testing.T) {
	d, _, c := newDeps(t, nil)
	d.Store.Update(func(s *state.State) { s.Baselines.LastRun["suid"] = c.t.Add(-time.Minute) })
	d.Store.ResetBaselines()
	if w, _ := d.resumeDelay("suid", 6*time.Hour); w != 0 {
		t.Fatalf("a baseline reset must force a fresh scan, got wait %v", w)
	}
}

func TestLastRunSurvivesRestart(t *testing.T) {
	d, _, c := newDeps(t, nil)
	d.Store.Update(func(s *state.State) { s.Baselines.LastRun["suid"] = c.t })
	if err := d.Store.Save(true); err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(d.Store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	st.View(func(s *state.State) {
		if !s.Baselines.LastRun["suid"].Equal(c.t) {
			t.Fatalf("last run lost across restart: %v", s.Baselines.LastRun["suid"])
		}
	})
}
