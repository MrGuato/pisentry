// Package event defines the pisentry event model and the Top 10 category catalog.
package event

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// SchemaVersion is the current pisentry event schema version.
const SchemaVersion = 1

var fallbackSeq atomic.Uint64

// NewID returns a unique RFC 4122 v4 UUID string for an event.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		n := fallbackSeq.Add(1)
		return fmt.Sprintf("%016x-%016x", uint64(time.Now().UnixNano()), n)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// IntPtr returns a pointer to v, used for optional integer fields where 0 is meaningful (such as root UID 0).
func IntPtr(v int) *int { return &v }

// Severity is an ordered event severity.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

// AllSeverities lists severities lowest to highest.
var AllSeverities = []Severity{Info, Low, Medium, High, Critical}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return sevNames[s]
}

// Weight is used to rank categories in the Top 10 report.
func (s Severity) Weight() int {
	return [...]int{0, 1, 2, 5, 10}[s]
}

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q", v)
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Bump raises a severity by n steps, capped at Critical.
func (s Severity) Bump(n int) Severity {
	v := int(s) + n
	if v > int(Critical) {
		v = int(Critical)
	}
	if v < int(Info) {
		v = int(Info)
	}
	return Severity(v)
}

// Category is a Top 10 category ID such as "PS01".
type Category string

const (
	Internal        Category = "PS00"
	SSHBruteForce   Category = "PS01"
	SuspiciousLogin Category = "PS02"
	InsecurePosture Category = "PS03"
	PrivEsc         Category = "PS04"
	Persistence     Category = "PS05"
	Cryptominer     Category = "PS06"
	NewListener     Category = "PS07"
	ReverseShell    Category = "PS08"
	PortScan        Category = "PS09"
	FileTamper      Category = "PS10"
)

// CategoryInfo describes one Top 10 category.
type CategoryInfo struct {
	ID          Category `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	MITRE       []string `json:"mitre"`
}

// Catalog is the pisentry Top 10, in ID order.
var Catalog = []CategoryInfo{
	{SSHBruteForce, "ssh-bruteforce", "SSH brute force",
		"Repeated failed SSH authentications from one source", []string{"T1110"}},
	{SuspiciousLogin, "suspicious-login", "Suspicious login",
		"Successful login after failures, from a new source, or as root", []string{"T1078"}},
	{InsecurePosture, "insecure-posture", "Insecure posture",
		"Weak SSH auth, default accounts, cleartext services, missing hardening", []string{"T1078.001", "T1021.004"}},
	{PrivEsc, "privilege-escalation", "Privilege escalation",
		"New SUID binaries, sudoers changes, privileged group changes, sudo/su abuse", []string{"T1548.001", "T1548.003"}},
	{Persistence, "persistence", "Persistence",
		"Cron, systemd units, authorized_keys, shell profile and udev changes", []string{"T1053.003", "T1543.002", "T1098.004", "T1546.004"}},
	{Cryptominer, "cryptominer", "Cryptominer",
		"Known miner binaries, stratum pool traffic, hot processes in temp dirs", []string{"T1496"}},
	{NewListener, "unexpected-listener", "Unexpected listener",
		"A network service started listening that is not in the baseline", []string{"T1571"}},
	{ReverseShell, "reverse-shell", "Reverse shell",
		"A shell or interpreter with its stdio wired to a TCP connection", []string{"T1059.004"}},
	{PortScan, "port-scan", "Port scan",
		"One source probing many ports, from firewall drop logs", []string{"T1046"}},
	{FileTamper, "critical-file-tamper", "Critical file tampering",
		"passwd/shadow, PAM, sshd_config, ld.so.preload and new privileged accounts", []string{"T1574.006", "T1556.003", "T1136.001"}},
}

// Lookup returns the catalog entry for a category.
func Lookup(c Category) CategoryInfo {
	for _, ci := range Catalog {
		if ci.ID == c {
			return ci
		}
	}
	if c == Internal {
		return CategoryInfo{ID: Internal, Slug: "internal", Name: "Agent operational"}
	}
	return CategoryInfo{ID: c, Name: string(c)}
}

// ProcessEntity holds typed process fields for Event Schema v1.
type ProcessEntity struct {
	PID       int    `json:"pid,omitempty"`
	PPID      int    `json:"ppid,omitempty"`
	StartTime uint64 `json:"start_time,omitempty"`
	UID       *int   `json:"uid,omitempty"`
	Comm      string `json:"comm,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
}

// SourceEntity holds typed network source or endpoint fields for Event Schema v1.
type SourceEntity struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// UserEntity holds typed account fields for Event Schema v1.
type UserEntity struct {
	Name string `json:"name,omitempty"`
	UID  *int   `json:"uid,omitempty"`
}

// FileEntity holds typed file integrity fields for Event Schema v1.
type FileEntity struct {
	Path       string `json:"path,omitempty"`
	HashBefore string `json:"hash_before,omitempty"`
	HashAfter  string `json:"hash_after,omitempty"`
}

// ContainerEntity holds typed container and Kubernetes workload fields for Event Schema v1.
type ContainerEntity struct {
	ID        string `json:"id,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// RuleEntity holds the rule or posture check identifier for Event Schema v1.
type RuleEntity struct {
	ID    string `json:"id,omitempty"`
	Title string `json:"title,omitempty"`
}

// Event is a single security finding emitted by a detector (Event Schema v1).
type Event struct {
	ID            string            `json:"id"`
	SchemaVersion int               `json:"schema_version"`
	Time          time.Time         `json:"time"`
	Host          string            `json:"host"`
	Category      Category          `json:"category"`
	CategoryName  string            `json:"category_name"`
	Severity      Severity          `json:"severity"`
	MITRE         []string          `json:"mitre,omitempty"`
	Detector      string            `json:"detector"`
	Summary       string            `json:"summary"`
	Key           string            `json:"key,omitempty"`
	Process       *ProcessEntity    `json:"process,omitempty"`
	Source        *SourceEntity     `json:"source,omitempty"`
	User          *UserEntity       `json:"user,omitempty"`
	File          *FileEntity       `json:"file,omitempty"`
	Container     *ContainerEntity  `json:"container,omitempty"`
	Rule          *RuleEntity       `json:"rule,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

// Emitter receives events from detectors.
type Emitter interface {
	Emit(Event)
}

// EmitFunc adapts a function to Emitter.
type EmitFunc func(Event)

func (f EmitFunc) Emit(e Event) { f(e) }

// Dur prints durations without trailing zero units: 5m0s -> 5m, 24h0m0s -> 24h.
func Dur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
