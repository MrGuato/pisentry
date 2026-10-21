package event

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewIDUniqueAndValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := NewID()
		if !reEventID.MatchString(id) {
			t.Fatalf("NewID() = %q, does not match pattern", id)
		}
		if seen[id] {
			t.Fatalf("duplicate ID %q", id)
		}
		seen[id] = true
	}
}

func TestSchemaFileSyncAndValidation(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "docs", "event-schema.json")
	b, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	var doc struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid json in %s: %v", schemaPath, err)
	}
	for _, k := range []string{
		"id", "schema_version", "time", "host", "category", "category_name",
		"severity", "mitre", "detector", "summary", "key",
		"process", "source", "user", "file", "container", "rule", "fields",
	} {
		if _, ok := doc.Properties[k]; !ok {
			t.Errorf("docs/event-schema.json missing property %q", k)
		}
	}

	ev := Event{
		ID:            NewID(),
		SchemaVersion: SchemaVersion,
		Time:          time.Date(2026, 10, 15, 5, 14, 2, 0, time.UTC),
		Host:          "kubepi",
		Category:      ReverseShell,
		CategoryName:  "Reverse shell",
		Severity:      Critical,
		MITRE:         []string{"T1059.004"},
		Detector:      "proc",
		Summary:       "Reverse shell: bash (pid 5358) has fd 0 connected to 192.0.2.2:4445",
		Key:           "5358:98112",
		Process: &ProcessEntity{
			PID:       5358,
			PPID:      1,
			StartTime: 98112,
			UID:       IntPtr(0),
			Comm:      "bash",
			Exe:       "/usr/bin/bash",
			Cmdline:   "bash -i",
		},
		Source: &SourceEntity{IP: "192.0.2.2", Port: 4445},
		User:   &UserEntity{Name: "root", UID: IntPtr(0)},
		File:   &FileEntity{Path: "/usr/bin/bash", HashBefore: "aaa", HashAfter: "bbb"},
		Container: &ContainerEntity{
			ID: "c123", Pod: "app-0", Namespace: "default",
		},
		Rule:   &RuleEntity{ID: "PS08-01", Title: "Interactive shell over TCP"},
		Fields: map[string]string{"pid": "5358", "uid": "0"},
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJSON(raw); err != nil {
		t.Fatalf("valid v1 event rejected: %v\njson: %s", err, raw)
	}

	// Verify root UID 0 is explicitly present in JSON, not omitted.
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	procMap := decoded["process"].(map[string]any)
	if uid, ok := procMap["uid"]; !ok || uid != float64(0) {
		t.Fatalf("expected process.uid=0 in JSON, got %v (ok=%v)", uid, ok)
	}

	// Unknown top-level field must fail.
	bad := append([]byte(`{"unexpected":1,`), raw[1:]...)
	if err := ValidateJSON(bad); err == nil {
		t.Fatal("expected unknown field to fail schema validation")
	}
}
