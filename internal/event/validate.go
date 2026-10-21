package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

var (
	reEventID  = regexp.MustCompile(`^[0-9a-f-]{16,64}$`)
	reCategory = regexp.MustCompile(`^PS[0-9]{2}$`)
	reMITRE    = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
)

// ValidateJSON checks that a raw JSON event payload conforms to Event Schema v1
// (docs/event-schema.json), including DisallowUnknownFields, required fields,
// and entity constraints.
func ValidateJSON(raw []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("invalid json object: %w", err)
	}
	for _, req := range []string{
		"id", "schema_version", "time", "host", "category", "category_name", "severity", "detector", "summary",
	} {
		if _, ok := m[req]; !ok {
			return fmt.Errorf("missing required field %q", req)
		}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var ev Event
	if err := dec.Decode(&ev); err != nil {
		return fmt.Errorf("strict decode failed: %w", err)
	}

	var timeStr string
	if err := json.Unmarshal(m["time"], &timeStr); err != nil {
		return fmt.Errorf("time must be string: %w", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, timeStr); err != nil {
		return fmt.Errorf("time %q is not RFC3339: %w", timeStr, err)
	}

	return Validate(ev)
}

// Validate checks an Event struct against Event Schema v1 invariants.
func Validate(ev Event) error {
	if !reEventID.MatchString(ev.ID) {
		return fmt.Errorf("id %q does not match ^[0-9a-f-]{16,64}$", ev.ID)
	}
	if ev.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version = %d, want %d", ev.SchemaVersion, SchemaVersion)
	}
	if ev.Time.IsZero() {
		return fmt.Errorf("time is zero")
	}
	if len(ev.Host) < 1 || len(ev.Host) > 256 {
		return fmt.Errorf("host length %d out of range [1,256]", len(ev.Host))
	}
	if !reCategory.MatchString(string(ev.Category)) {
		return fmt.Errorf("category %q does not match ^PS[0-9]{2}$", ev.Category)
	}
	if len(ev.CategoryName) < 1 || len(ev.CategoryName) > 128 {
		return fmt.Errorf("category_name length %d out of range [1,128]", len(ev.CategoryName))
	}
	if ev.Severity < Info || ev.Severity > Critical {
		return fmt.Errorf("invalid severity %d", ev.Severity)
	}
	for _, m := range ev.MITRE {
		if !reMITRE.MatchString(m) {
			return fmt.Errorf("mitre technique %q does not match ^T[0-9]{4}(\\.[0-9]{3})?$", m)
		}
	}
	if len(ev.Detector) < 1 || len(ev.Detector) > 64 {
		return fmt.Errorf("detector length %d out of range [1,64]", len(ev.Detector))
	}
	if len(ev.Summary) < 1 || len(ev.Summary) > 403 {
		return fmt.Errorf("summary length %d out of range [1,403]", len(ev.Summary))
	}
	if len(ev.Key) > 512 {
		return fmt.Errorf("key length %d exceeds 512", len(ev.Key))
	}
	if p := ev.Process; p != nil {
		if p.PID < 0 || p.PPID < 0 {
			return fmt.Errorf("process pid/ppid must be non-negative")
		}
		if p.UID != nil && *p.UID < 0 {
			return fmt.Errorf("process.uid %d must be >= 0", *p.UID)
		}
		if len(p.Comm) > 131 || len(p.Exe) > 515 || len(p.Cmdline) > 515 {
			return fmt.Errorf("process string field exceeds max length")
		}
	}
	if s := ev.Source; s != nil {
		if len(s.IP) > 131 || s.Port < 0 || s.Port > 65535 {
			return fmt.Errorf("source field out of bounds")
		}
	}
	if u := ev.User; u != nil {
		if len(u.Name) > 131 || (u.UID != nil && *u.UID < 0) {
			return fmt.Errorf("user field out of bounds")
		}
	}
	if f := ev.File; f != nil {
		if len(f.Path) > 515 || len(f.HashBefore) > 131 || len(f.HashAfter) > 131 {
			return fmt.Errorf("file field exceeds max length")
		}
	}
	if c := ev.Container; c != nil {
		if len(c.ID) > 131 || len(c.Pod) > 259 || len(c.Namespace) > 131 {
			return fmt.Errorf("container field exceeds max length")
		}
	}
	if r := ev.Rule; r != nil {
		if len(r.ID) > 131 || len(r.Title) > 259 {
			return fmt.Errorf("rule field exceeds max length")
		}
	}
	for k, v := range ev.Fields {
		if len(v) > 515 {
			return fmt.Errorf("fields[%q] length %d exceeds 515", k, len(v))
		}
	}
	return nil
}
