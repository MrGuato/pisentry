// Package state persists baselines, counters and recent events to disk so
// pisentry survives restarts without re-learning or losing its Top 10 history.
package state

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/MrGuato/pisentry/internal/audit"
	"github.com/MrGuato/pisentry/internal/event"
)

const (
	FileName      = "state.json"
	ResetTrigger  = "reset-baseline"
	maxRecent     = 1000
	schemaVersion = 1
)

// FileSig is a file fingerprint used by FIM and the SUID scanner.
type FileSig struct {
	Hash string `json:"hash,omitempty"`
	Mode uint32 `json:"mode"`
	UID  int    `json:"uid"`
	Size int64  `json:"size"`
	Link string `json:"link,omitempty"`
}

type Listener struct {
	Proto     string    `json:"proto"`
	Addr      string    `json:"addr"`
	Port      int       `json:"port"`
	Process   string    `json:"process,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

type Baselines struct {
	FIM            map[string]FileSig              `json:"fim"`
	FIMReady       bool                            `json:"fim_ready"`
	Accounts       map[string]string               `json:"accounts"` // user -> "uid:shell"
	PrivGroups     map[string][]string             `json:"priv_groups"`
	Listeners      map[string]Listener             `json:"listeners"`
	ListenersSince time.Time                       `json:"listeners_since"`
	SUID           map[string]FileSig              `json:"suid"`
	SUIDReady      bool                            `json:"suid_ready"`
	Logins         map[string]map[string]time.Time `json:"logins"` // user -> ip -> last seen
	// LastRun is when each slow detector last finished a scan. It lives with
	// the baselines so a baseline reset also forces a fresh scan.
	LastRun map[string]time.Time `json:"last_run,omitempty"`
}

type State struct {
	Version   int                    `json:"version"`
	Created   time.Time              `json:"created"`
	Host      string                 `json:"host"`
	Saved     time.Time              `json:"saved"`
	Baselines Baselines              `json:"baselines"`
	Totals    map[event.Category]int `json:"totals"`
	Recent    []event.Event          `json:"recent"`
	Audit     []audit.Finding        `json:"audit"`
	AuditTime time.Time              `json:"audit_time"`
}

func newState() State {
	s := State{Version: schemaVersion, Created: time.Now().UTC()}
	s.init()
	return s
}

func (s *State) init() {
	if s.Totals == nil {
		s.Totals = map[event.Category]int{}
	}
	b := &s.Baselines
	if b.FIM == nil {
		b.FIM = map[string]FileSig{}
	}
	if b.Accounts == nil {
		b.Accounts = map[string]string{}
	}
	if b.PrivGroups == nil {
		b.PrivGroups = map[string][]string{}
	}
	if b.Listeners == nil {
		b.Listeners = map[string]Listener{}
	}
	if b.SUID == nil {
		b.SUID = map[string]FileSig{}
	}
	if b.Logins == nil {
		b.Logins = map[string]map[string]time.Time{}
	}
	if b.LastRun == nil {
		b.LastRun = map[string]time.Time{}
	}
}

// Store guards State with a mutex and handles atomic persistence.
type Store struct {
	mu    sync.Mutex
	dir   string
	s     State
	dirty bool
	// Recovered is set to the quarantined path when a corrupt state file was found.
	Recovered string
}

// Open loads state from dir, or starts fresh if none exists.
func Open(dir string) (*Store, error) {
	st := &Store{dir: dir, s: newState()}
	path := filepath.Join(dir, FileName)
	s, err := ReadFile(path)
	switch {
	case err == nil:
		st.s = s
	case errors.Is(err, os.ErrNotExist):
	case errors.As(err, new(*json.SyntaxError)), errors.As(err, new(*json.UnmarshalTypeError)), errors.Is(err, io.ErrUnexpectedEOF):
		// A Pi losing power mid-write must not crash-loop the agent forever.
		// Keep the bad file for forensics and start fresh (baselines re-learn).
		bad := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405")
		_ = os.Rename(path, bad)
		st.Recovered = bad
	default:
		return nil, err
	}
	return st, nil
}

// ReadFile reads a state file without taking ownership of it (used by the CLI).
func ReadFile(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	s.init()
	return s, nil
}

func (st *Store) Dir() string { return st.dir }

// Update runs fn with the lock held and marks state dirty.
func (st *Store) Update(fn func(*State)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
	st.dirty = true
}

// View runs fn with the lock held, read-only by convention.
func (st *Store) View(fn func(*State)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
}

// Record adds an event to totals and the recent ring buffer.
func (st *Store) Record(e event.Event) {
	st.Update(func(s *State) {
		s.Totals[e.Category]++
		s.Recent = append(s.Recent, e)
		if n := len(s.Recent); n > maxRecent {
			s.Recent = append([]event.Event(nil), s.Recent[n-maxRecent:]...)
		}
	})
}

// ResetBaselines drops every learned baseline. Counters and history stay.
func (st *Store) ResetBaselines() {
	st.Update(func(s *State) {
		s.Baselines = Baselines{}
		s.init()
	})
}

// Save writes state atomically if it changed.
func (st *Store) Save(force bool) error {
	st.mu.Lock()
	if !st.dirty && !force {
		st.mu.Unlock()
		return nil
	}
	st.s.Saved = time.Now().UTC()
	b, err := json.Marshal(st.s)
	st.dirty = false
	st.mu.Unlock()
	if err == nil {
		err = writeAtomic(st.dir, b)
	}
	if err != nil {
		st.mu.Lock()
		st.dirty = true // retry on the next save
		st.mu.Unlock()
	}
	return err
}

// writeAtomic writes tmp, fsyncs it, renames over state.json and fsyncs the
// directory, so a power cut leaves either the old or the new file intact.
func writeAtomic(dir string, b []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, FileName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, FileName)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// CheckResetTrigger handles `pisentry baseline reset` issued while the agent runs.
func (st *Store) CheckResetTrigger() bool {
	p := filepath.Join(st.dir, ResetTrigger)
	if _, err := os.Stat(p); err != nil {
		return false
	}
	st.ResetBaselines()
	_ = os.Remove(p)
	return true
}
