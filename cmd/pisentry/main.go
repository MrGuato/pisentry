// Command pisentry is a lightweight host security agent for Raspberry Pi and
// other ARM Linux boxes. It reports the "Top 10" attack categories seen on the
// host and audits basic posture.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/MrGuato/pisentry/internal/alert"
	"github.com/MrGuato/pisentry/internal/audit"
	"github.com/MrGuato/pisentry/internal/config"
	"github.com/MrGuato/pisentry/internal/detect"
	"github.com/MrGuato/pisentry/internal/engine"
	"github.com/MrGuato/pisentry/internal/event"
	"github.com/MrGuato/pisentry/internal/metrics"
	"github.com/MrGuato/pisentry/internal/report"
	"github.com/MrGuato/pisentry/internal/state"
)

var version = "dev"

const defaultConfig = "/etc/pisentry/config.json"

func usage() {
	fmt.Fprintf(os.Stderr, `pisentry %s - Top 10 attack reporting for Raspberry Pi and ARM Linux

Usage:
  pisentry run        [-config FILE]                 run the agent
  pisentry report     [-config FILE] [-since 24h] [-json]
                                                     ranked Top 10 from saved state
  pisentry audit      [-config FILE] [-json]         one-shot posture audit (exit 2 on high/critical)
  pisentry baseline   reset [-config FILE]           re-learn FIM/listener/SUID baselines
  pisentry test-alert [-config FILE]                 send a test webhook alert
  pisentry categories                                print the Top 10 catalog
  pisentry version
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "audit":
		code, err = cmdAudit(os.Args[2:])
	case "baseline":
		err = cmdBaseline(os.Args[2:])
	case "test-alert":
		err = cmdTestAlert(os.Args[2:])
	case "categories":
		for _, c := range event.Catalog {
			fmt.Printf("%s  %-24s %-28s %s\n", c.ID, c.Name, fmt.Sprint(c.MITRE), c.Description)
		}
	case "version", "-v", "--version":
		fmt.Printf("pisentry %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", defaultConfig, "config file (JSON)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg, err := config.Load(*path)
	return &cfg, err
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	host := cfg.ResolveHostname()

	store, err := state.Open(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	if store.Recovered != "" {
		log.Warn("state file was corrupt; moved aside and starting fresh", "quarantined", store.Recovered)
	}
	store.Update(func(s *state.State) { s.Host = host })
	if err := store.Save(true); err != nil {
		return fmt.Errorf("state dir %s not writable: %w", cfg.StateDir, err)
	}

	m := metrics.NewSet()
	m.Up.Set(1, host)
	m.BuildInfo.Set(1, version, runtime.GOARCH)
	eng := engine.New(cfg, host, store, m)
	if cfg.Output.Stdout {
		eng.AddSink(engine.NewJSONSink(os.Stdout))
	}
	if cfg.Output.JSONFile != "" {
		js, err := engine.OpenJSONFile(cfg.Output.JSONFile)
		if err != nil {
			return err
		}
		eng.AddSink(js)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	wh, err := alert.New(cfg.Alerts, m, log)
	if err != nil {
		// Do not crash-loop because a webhook secret is missing; detection
		// matters more than notification.
		log.Error("alerts disabled", "err", err)
	} else if wh != nil {
		eng.AddSink(wh)
		go wh.Run(ctx)
		log.Info("alerts enabled", "type", cfg.Alerts.Type, "min_severity", cfg.Alerts.MinSeverity.String())
	}

	d := detect.Deps{Cfg: cfg, Emit: eng, Store: store, M: m, Log: log}
	log.Info("pisentry starting", "version", version, "host", host, "host_root", cfg.HostRoot,
		"state", cfg.StateDir, "learning_period", cfg.LearningPeriod.Duration.String())

	var auth *detect.Auth
	var ps *detect.PortScan
	if cfg.Enabled("auth") {
		auth = detect.NewAuth(d)
	}
	if cfg.Enabled("portscan") {
		ps = detect.NewPortScan(d)
	}
	if auth != nil || ps != nil {
		go detect.RunLogs(ctx, d, auth, ps)
	}
	type runner interface{ Run(context.Context) }
	runners := map[string]runner{
		"fim":       detect.NewFIM(d),
		"listeners": detect.NewListeners(d),
		"proc":      detect.NewProcWatch(d),
		"suid":      detect.NewSUID(d),
		"audit":     detect.NewAuditRunner(d),
	}
	for name, r := range runners {
		if cfg.Enabled(name) {
			go r.Run(ctx)
		} else {
			log.Info("detector disabled", "detector", name)
		}
	}

	if cfg.Listen != "" {
		srv := &http.Server{Addr: cfg.Listen, Handler: mux(cfg, store, m), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info("http listening", "addr", cfg.Listen)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("http server", "err", err)
			}
		}()
		defer srv.Shutdown(context.Background())
	}

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return store.Save(true)
		case <-t.C:
			if store.CheckResetTrigger() {
				log.Warn("baseline reset requested; re-learning")
			}
			if err := store.Save(false); err != nil {
				log.Error("save state", "err", err)
			}
		}
	}
}

func mux(cfg *config.Config, store *state.Store, m *metrics.Set) *http.ServeMux {
	mx := http.NewServeMux()
	mx.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = m.Reg.Write(w)
	})
	mx.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mx.HandleFunc("GET /api/top10", func(w http.ResponseWriter, r *http.Request) {
		win := 24 * time.Hour
		if v := r.URL.Query().Get("window"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				win = d
			}
		}
		var snap state.State
		store.View(func(s *state.State) { snap = copyForReport(s) })
		writeJSON(w, report.Build(snap, win, time.Now()))
	})
	mx.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		var out []event.Event
		store.View(func(s *state.State) {
			n := len(s.Recent)
			start := n - limit
			if start < 0 {
				start = 0
			}
			for i := n - 1; i >= start; i-- {
				out = append(out, s.Recent[i])
			}
		})
		writeJSON(w, out)
	})
	return mx
}

// copyForReport copies only what report.Build reads, so the lock is short.
func copyForReport(s *state.State) state.State {
	c := state.State{Host: s.Host, Saved: time.Now(), AuditTime: s.AuditTime, Totals: map[event.Category]int{}}
	for k, v := range s.Totals {
		c.Totals[k] = v
	}
	c.Recent = append([]event.Event(nil), s.Recent...)
	c.Audit = append([]audit.Finding(nil), s.Audit...)
	return c
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	since := fs.Duration("since", 24*time.Hour, "time window")
	asJSON := fs.Bool("json", false, "JSON output")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	s, err := state.ReadFile(filepath.Join(cfg.StateDir, state.FileName))
	if err != nil {
		return fmt.Errorf("read state (is the agent running, and are you root?): %w", err)
	}
	r := report.Build(s, *since, time.Now())
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	r.Text(os.Stdout)
	return nil
}

func cmdAudit(args []string) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return 1, err
	}
	findings := audit.Run(cfg)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(findings)
	} else {
		report.AuditText(os.Stdout, cfg.ResolveHostname(), findings)
	}
	for _, f := range findings {
		if f.Status == audit.Fail && f.Severity >= event.High {
			return 2, nil
		}
	}
	return 0, nil
}

func cmdBaseline(args []string) error {
	if len(args) < 1 || args[0] != "reset" {
		return errors.New("usage: pisentry baseline reset [-config FILE]")
	}
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	p := filepath.Join(cfg.StateDir, state.ResetTrigger)
	if err := os.WriteFile(p, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("baseline reset requested; the running agent picks it up within 30s and re-learns for", cfg.LearningPeriod.Duration)
	return nil
}

func cmdTestAlert(args []string) error {
	fs := flag.NewFlagSet("test-alert", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	wh, err := alert.New(cfg.Alerts, metrics.NewSet(), log)
	if err != nil {
		return err
	}
	if wh == nil {
		return errors.New("alerts.type is not set in the config")
	}
	ev := event.Event{
		Time: time.Now().UTC(), Host: cfg.ResolveHostname(), Category: event.SSHBruteForce,
		CategoryName: "SSH brute force", Severity: event.High, Detector: "test",
		Summary: "Test alert from pisentry. If you can read this, webhook delivery works.",
		MITRE:   []string{"T1110"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := wh.Send(ctx, ev); err != nil {
		return err
	}
	fmt.Println("test alert sent")
	return nil
}
