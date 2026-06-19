// Command sentinel is the main service binary: it loads configuration,
// constructs the BucketStore/Scheduler, starts the client API, admin API,
// and metrics listeners, and shuts everything down gracefully on
// SIGINT/SIGTERM (design.md 4.10).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/bucket"
	"sentinel/internal/config"
	"sentinel/internal/fairness"
	"sentinel/internal/metrics"
	"sentinel/internal/scheduler"
	"sentinel/internal/server"
	"sentinel/internal/store"
	"sentinel/internal/window"
)

func main() {
	configPath := flag.String("config", "configs/sentinel.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelFromString(cfg.Logging.Level)}))
	slog.SetDefault(logger)

	auditBase := logger
	var auditFile *os.File
	if cfg.Logging.AuditFile != "" {
		f, err := os.OpenFile(cfg.Logging.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			logger.Error("failed to open audit file, falling back to stdout", "error", err, "path", cfg.Logging.AuditFile)
		} else {
			auditFile = f
			auditBase = slog.New(slog.NewJSONHandler(f, nil))
		}
	}
	auditLogger := audit.New(auditBase, cfg.Logging.RequestSampleRate)

	tierDefaults := map[string]bucket.Config{
		"default": toBucketConfig(cfg.Defaults),
	}
	for name, bd := range cfg.Tiers {
		tierDefaults[name] = toBucketConfig(bd)
	}

	st := store.New(store.Options{
		MaxClients:   cfg.Limits.MaxClients,
		TierDefaults: tierDefaults,
		Logger:       logger,
	})

	sched := scheduler.New(st.OnDue, logger)
	st.AttachScheduler(sched)

	now := time.Now()
	if cfg.Global.Enabled {
		st.SetGlobalConfig(bucket.Config{
			MaxTokens:        cfg.Global.MaxTokens,
			RefillRate:       cfg.Global.RefillRate,
			RefillInterval:   cfg.Global.RefillInterval,
			TokensPerRequest: 1,
		}, now)
	}
	if cfg.Security.EnableIPSecondaryLimit {
		st.SetIPLimit(true, bucket.Config{
			MaxTokens:        cfg.Security.IPMaxTokens,
			RefillRate:       cfg.Security.IPRefillRate,
			RefillInterval:   cfg.Security.IPRefillInterval,
			TokensPerRequest: 1,
		})
	}

	fairnessTracker := fairness.New(cfg.Fairness.Enabled, cfg.Fairness.DefaultWeight)
	reg := metrics.NewRegistry()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sched.Run(ctx)
	go reportMetricsLoop(ctx, st, sched, reg)

	clientSrv := server.NewClientServer(cfg, st, fairnessTracker, auditLogger, reg, logger)
	adminSrv := server.NewAdminServer(cfg, st, fairnessTracker, auditLogger, reg, logger)

	var metricsHTTP *http.Server
	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", reg.Handler())
		metricsHTTP = &http.Server{Addr: fmt.Sprintf(":%d", cfg.Metrics.Port), Handler: mux}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := clientSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("client server stopped", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server stopped", "error", err)
		}
	}()
	if metricsHTTP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("metrics listening", "addr", metricsHTTP.Addr)
			if err := metricsHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server stopped", "error", err)
			}
		}()
	}

	logger.Info("sentinel started",
		"client_port", cfg.Server.ClientPort,
		"admin_port", cfg.Server.AdminPort,
		"max_clients", cfg.Limits.MaxClients,
	)

	<-ctx.Done()
	logger.Info("shutdown signal received, draining in-flight requests")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = clientSrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
	if metricsHTTP != nil {
		_ = metricsHTTP.Shutdown(shutdownCtx)
	}

	wg.Wait()
	if auditFile != nil {
		_ = auditFile.Close()
	}
	logger.Info("sentinel stopped cleanly")
}

// reportMetricsLoop periodically samples store/scheduler state into the
// metrics registry's gauges, which are not naturally event-driven the way
// the counters are.
func reportMetricsLoop(ctx context.Context, st *store.BucketStore, sched *scheduler.Scheduler, reg *metrics.Registry) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reg.ActiveClients.Set(int64(st.ActiveClients()))
			reg.SchedulerHeapSize.Set(int64(sched.HeapSize()))
			reg.SchedulerRefills.Set(sched.RefillsTotal())
			reg.EvictionsTotal.Set(st.Evictions())
		}
	}
}

// toBucketConfig translates config.BucketDefaults (the plain config-layer
// shape) into bucket.Config (the runtime shape), including the optional
// sliding-window sub-config (B1).
func toBucketConfig(bd config.BucketDefaults) bucket.Config {
	cfg := bucket.Config{
		MaxTokens:        bd.MaxTokens,
		RefillRate:       bd.RefillRate,
		RefillInterval:   bd.RefillInterval,
		TokensPerRequest: bd.TokensPerRequest,
	}
	if bd.SlidingWindow != nil && bd.SlidingWindow.Enabled {
		cfg.SlidingWindow = &window.Config{
			Enabled:        true,
			WindowDuration: bd.SlidingWindow.WindowDuration,
			MaxRequests:    bd.SlidingWindow.MaxRequests,
			BufferSize:     bd.SlidingWindow.BufferSize,
		}
	}
	return cfg
}

func levelFromString(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
