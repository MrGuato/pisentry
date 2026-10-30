// Package config loads the pisentry JSON configuration.
//
// Every field is optional. Defaults() returns a config that works on a
// stock Raspberry Pi OS / Ubuntu / RHEL host running under systemd.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MrGuato/pisentry/internal/event"
)

// Duration is a time.Duration that marshals as "5m", "30s", etc.
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func D(v time.Duration) Duration { return Duration{v} }

type Config struct {
	// HostRoot is where the host filesystem is visible. "/" on bare metal,
	// "/host" inside the Kubernetes DaemonSet.
	HostRoot string `json:"host_root"`
	// ProcRoot is the procfs mount. With hostPID the container's /proc is the host's.
	ProcRoot string `json:"proc_root"`
	StateDir string `json:"state_dir"`
	Hostname string `json:"hostname"`
	// Listen is the HTTP address for /metrics and /api. Empty disables it.
	Listen         string   `json:"listen"`
	LearningPeriod Duration `json:"learning_period"`
	// Cooldown suppresses repeat events with the same category+key.
	Cooldown Duration `json:"cooldown"`
	Disable  []string `json:"disable"`

	Logs      LogConfig      `json:"logs"`
	Rules     RulesConfig    `json:"rules"`
	SSH       SSHConfig      `json:"ssh"`
	PortScan  PortScanConfig `json:"portscan"`
	FIM       FIMConfig      `json:"fim"`
	Listeners ListenerConfig `json:"listeners"`
	Proc      ProcConfig     `json:"proc"`
	SUID      SUIDConfig     `json:"suid"`
	Audit     AuditConfig    `json:"audit"`
	Output    OutputConfig   `json:"output"`
	Alerts    AlertConfig    `json:"alerts"`
}

type LogConfig struct {
	// Source is "auto", "journald" or "file".
	Source string `json:"source"`
	// Files to tail in file mode (host paths). Missing files are skipped.
	Files []string `json:"files"`
	// JournalChroot runs journalctl from the host (chroot into HostRoot) so the
	// journal reader always matches the host's systemd version. Used in k8s.
	JournalChroot bool `json:"journal_chroot"`
	// SSHRequireRoot drops journald sshd records not logged by uid 0, so a
	// local user cannot forge sshd lines with logger(1). No effect in file mode.
	SSHRequireRoot bool `json:"ssh_require_root"`
}

// RulesConfig locates operator rule bundles.
type RulesConfig struct {
	// Dir is the directory of JSON rule bundles loaded over the built-in default.json.
	Dir string `json:"dir"`
	// ReloadInterval is how often Dir is checked for changes. "0s" turns the
	// watch off; SIGHUP still reloads.
	ReloadInterval Duration `json:"reload_interval"`
}

type SSHConfig struct {
	FailThreshold          int      `json:"fail_threshold"`
	FailWindow             Duration `json:"fail_window"`
	SuccessAfterFailWindow Duration `json:"success_after_fail_window"`
	SuccessAfterFailMin    int      `json:"success_after_fail_min"`
	AllowCIDRs             []string `json:"allow_cidrs"`
}

type PortScanConfig struct {
	Threshold  int      `json:"threshold"`
	Window     Duration `json:"window"`
	AllowCIDRs []string `json:"allow_cidrs"`
}

type WatchSpec struct {
	Pattern   string         `json:"pattern"`
	Category  event.Category `json:"category"`
	Severity  event.Severity `json:"severity"`
	Recursive bool           `json:"recursive"`
}

type FIMConfig struct {
	Interval   Duration    `json:"interval"`
	ExtraWatch []WatchSpec `json:"extra_watch"`
}

type ListenerConfig struct {
	Interval       Duration `json:"interval"`
	IgnoreLoopback bool     `json:"ignore_loopback"`
	AllowPorts     []int    `json:"allow_ports"`
}

type ProcConfig struct {
	Interval Duration `json:"interval"`
	// CPUThreshold is percent of one core (100 = one full core).
	CPUThreshold float64 `json:"cpu_threshold"`
	// SustainedPolls of high CPU with no other indicator raises a low-severity event.
	SustainedPolls int `json:"sustained_polls"`
	// MinerNames is an extra list of miner names matched on top of the
	// PS06-MINER-* rules. Empty by default; the built-in list is in the rules.
	MinerNames []string `json:"miner_names"`
	// StratumPorts and ShellNames replace the rule catalog lists when set.
	StratumPorts []int    `json:"stratum_ports"`
	AllowComm    []string `json:"allow_comm"`
	ShellNames   []string `json:"shell_names"`
	// RevShellIgnoreLoopback skips shells connected to 127.0.0.1/::1.
	RevShellIgnoreLoopback bool `json:"revshell_ignore_loopback"`
}

type SUIDConfig struct {
	Interval Duration `json:"interval"`
	Paths    []string `json:"paths"`
}

type AuditConfig struct {
	Interval Duration `json:"interval"`
}

type OutputConfig struct {
	Stdout   bool   `json:"stdout"`
	JSONFile string `json:"json_file"`
}

type AlertConfig struct {
	// Type is "ntfy", "discord", "slack" or "generic". Empty disables alerts.
	Type        string         `json:"type"`
	URL         string         `json:"url"`
	URLEnv      string         `json:"url_env"`
	TokenEnv    string         `json:"token_env"`
	MinSeverity event.Severity `json:"min_severity"`
	MaxPerHour  int            `json:"max_per_hour"`
}

// Defaults returns a working configuration for a bare-metal systemd install.
func Defaults() Config {
	return Config{
		HostRoot:       "/",
		ProcRoot:       "/proc",
		StateDir:       "/var/lib/pisentry",
		Listen:         "127.0.0.1:9817",
		LearningPeriod: D(10 * time.Minute),
		Cooldown:       D(15 * time.Minute),
		Logs: LogConfig{
			Source:         "auto",
			SSHRequireRoot: true,
			Files:          []string{"/var/log/auth.log", "/var/log/secure", "/var/log/kern.log", "/var/log/messages"},
		},
		Rules: RulesConfig{
			Dir:            "/etc/pisentry/rules.d",
			ReloadInterval: D(10 * time.Second),
		},
		SSH: SSHConfig{
			FailThreshold:          5,
			FailWindow:             D(5 * time.Minute),
			SuccessAfterFailWindow: D(15 * time.Minute),
			SuccessAfterFailMin:    3,
		},
		PortScan: PortScanConfig{Threshold: 12, Window: D(60 * time.Second)},
		FIM:      FIMConfig{Interval: D(60 * time.Second)},
		Listeners: ListenerConfig{
			Interval:       D(30 * time.Second),
			IgnoreLoopback: true,
		},
		Proc: ProcConfig{
			Interval:       D(15 * time.Second),
			CPUThreshold:   80,
			SustainedPolls: 40,
			AllowComm: []string{
				"prometheus", "k3s-server", "k3s-agent", "k3s", "containerd", "kubelet",
				"grafana", "couchdb", "beam.smp", "apt", "apt-get", "dpkg", "dnf", "rpm",
				"cc1", "cc1plus", "go", "rustc", "cargo", "gcc", "ld", "make", "unattended-upgr",
			},
			RevShellIgnoreLoopback: true,
		},
		SUID: SUIDConfig{
			Interval: D(6 * time.Hour),
			Paths: []string{
				"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib",
				"/usr/libexec", "/opt", "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/srv",
			},
		},
		Audit:  AuditConfig{Interval: D(6 * time.Hour)},
		Output: OutputConfig{Stdout: true},
		Alerts: AlertConfig{
			URLEnv:      "PISENTRY_WEBHOOK_URL",
			TokenEnv:    "PISENTRY_WEBHOOK_TOKEN",
			MinSeverity: event.High,
			MaxPerHour:  30,
		},
	}
}

// Load reads path (if it exists) over the defaults and applies env overrides.
// Unknown keys are an error, so a typo does not silently disable a setting.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// defaults only
		case err != nil:
			return cfg, err
		default:
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&cfg); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", path, err)
			}
		}
	}
	if v := os.Getenv("PISENTRY_HOST_ROOT"); v != "" {
		cfg.HostRoot = v
	}
	if v := os.Getenv("PISENTRY_STATE_DIR"); v != "" {
		cfg.StateDir = v
	}
	if v := os.Getenv("PISENTRY_RULES_DIR"); v != "" {
		cfg.Rules.Dir = v
	}
	// Lets a Kubernetes Secret switch alerts on without patching the ConfigMap.
	if v := os.Getenv("PISENTRY_ALERT_TYPE"); v != "" {
		cfg.Alerts.Type = v
	}
	if v := os.Getenv("NODE_NAME"); v != "" && cfg.Hostname == "" {
		cfg.Hostname = v
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	switch c.Logs.Source {
	case "auto", "journald", "file", "none":
	default:
		return fmt.Errorf("logs.source must be auto, journald, file or none")
	}
	switch c.Alerts.Type {
	case "", "ntfy", "discord", "slack", "generic":
	default:
		return fmt.Errorf("alerts.type must be ntfy, discord, slack or generic")
	}
	if c.SSH.FailThreshold < 1 || c.PortScan.Threshold < 2 {
		return fmt.Errorf("thresholds too low")
	}
	for name, d := range map[string]Duration{
		"fim.interval": c.FIM.Interval, "listeners.interval": c.Listeners.Interval,
		"proc.interval": c.Proc.Interval, "suid.interval": c.SUID.Interval,
		"audit.interval": c.Audit.Interval, "ssh.fail_window": c.SSH.FailWindow,
		"portscan.window": c.PortScan.Window,
	} {
		if d.Duration < time.Second {
			return fmt.Errorf("%s must be at least 1s", name)
		}
	}
	if r := c.Rules.ReloadInterval.Duration; r != 0 && r < time.Second {
		return fmt.Errorf("rules.reload_interval must be 0s (off) or at least 1s")
	}
	return nil
}

// HostPath maps an absolute host path into HostRoot.
func (c *Config) HostPath(p string) string {
	if c.HostRoot == "" || c.HostRoot == "/" {
		return p
	}
	return filepath.Join(c.HostRoot, p)
}

// StripHost converts a HostRoot-prefixed path back into the host's view.
func (c *Config) StripHost(p string) string {
	if c.HostRoot == "" || c.HostRoot == "/" {
		return p
	}
	r := strings.TrimPrefix(p, filepath.Clean(c.HostRoot))
	if r == "" {
		return "/"
	}
	return r
}

// Enabled reports whether a detector is not disabled.
func (c *Config) Enabled(name string) bool {
	for _, d := range c.Disable {
		if d == name {
			return false
		}
	}
	return true
}

// ResolveHostname picks the name used in events.
func (c *Config) ResolveHostname() string {
	if c.Hostname != "" {
		return c.Hostname
	}
	if c.HostRoot != "/" && c.HostRoot != "" {
		if b, err := os.ReadFile(c.HostPath("/etc/hostname")); err == nil {
			if h := strings.TrimSpace(string(b)); h != "" {
				return h
			}
		}
	}
	h, _ := os.Hostname()
	return h
}
