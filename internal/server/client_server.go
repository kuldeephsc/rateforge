// ClientServer implements the client-facing decision API (FR2/FR5/FR9):
// POST /api/v1/request -> 200 (allowed) or 429 + Retry-After (rejected).
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/config"
	"sentinel/internal/fairness"
	"sentinel/internal/metrics"
	"sentinel/internal/security"
	"sentinel/internal/store"
)

// ClientServer wires the BucketStore up to an HTTP listener for the
// client-facing API.
type ClientServer struct {
	cfg      *config.Config
	store    *store.BucketStore
	fairness *fairness.Tracker
	audit    *audit.Logger
	metrics  *metrics.Registry
	logger   *slog.Logger

	httpServer *http.Server
}

// NewClientServer constructs a ClientServer. Call ListenAndServe to start
// it (typically in its own goroutine).
func NewClientServer(cfg *config.Config, st *store.BucketStore, ft *fairness.Tracker, al *audit.Logger, reg *metrics.Registry, logger *slog.Logger) *ClientServer {
	return &ClientServer{cfg: cfg, store: st, fairness: ft, audit: al, metrics: reg, logger: logger}
}

type allowResponse struct {
	Allowed         bool   `json:"allowed"`
	RemainingTokens int64  `json:"remaining_tokens"`
	RetryAfterMs    int64  `json:"retry_after_ms,omitempty"`
	ResetAt         string `json:"reset_at,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	// Generic, internals-free error messages per design.md 4.5 ("All
	// validation failures -> 400 Bad Request with generic message").
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleRequest is the sole client-facing endpoint.
func (s *ClientServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.ContentLength > 0 {
		// FR/4.5: client request body is unexpected; reject if present.
		writeError(w, http.StatusBadRequest, "request body not expected")
		return
	}

	ip := sourceIP(r, s.cfg.Security.TrustProxyHeaders)
	key, _ := clientIdentity(r, ip, s.cfg.Security.IdentityMode)

	if key == "" {
		writeError(w, http.StatusBadRequest, "missing client identity")
		return
	}
	if err := security.ValidateAPIKey(key); err != nil {
		s.audit.Anomaly("invalid_client_identity", security.SanitizeForLog(key), ip)
		writeError(w, http.StatusBadRequest, "invalid client identity")
		return
	}

	tier := r.Header.Get("X-Resource-Tier")
	if err := security.ValidateTier(tier); err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource tier")
		return
	}

	now := time.Now()
	result := s.store.Allow(store.AllowRequest{ClientKey: key, SourceIP: ip, Tier: tier, Now: now})
	latency := time.Since(start)

	s.audit.RequestDecision(result.Allowed, key, ip, result.RemainingTokens, latency)
	if s.metrics != nil {
		decision := "reject"
		if result.Allowed {
			decision = "allow"
		} else if result.Reason == "blocked" {
			decision = "blocked"
		}
		s.metrics.RequestsTotal.Inc(decision)
		s.metrics.RequestLatency.Observe(latency.Seconds())
	}

	if result.Allowed {
		if s.fairness != nil && s.fairness.Enabled() {
			s.fairness.RecordConsumption(key, 1)
		}
		writeJSON(w, http.StatusOK, allowResponse{
			Allowed:         true,
			RemainingTokens: result.RemainingTokens,
		})
		return
	}

	w.Header().Set("Retry-After", strconv.FormatFloat(result.RetryAfter.Seconds(), 'f', 3, 64))
	writeJSON(w, http.StatusTooManyRequests, allowResponse{
		Allowed:      false,
		RetryAfterMs: result.RetryAfter.Milliseconds(),
		ResetAt:      now.Add(result.RetryAfter).UTC().Format(time.RFC3339),
	})
}

// ListenAndServe starts the client API listener (TLS if configured per
// FR9, otherwise plain HTTP with a loud warning — intended for local
// development only) and blocks serving until Shutdown is called.
func (s *ClientServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/request", s.handleRequest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	s.httpServer = &http.Server{
		Handler:        RecoverMiddleware(s.logger, mux),
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 4 << 10, // 4 KB, per design.md 4.6
	}

	addr := fmt.Sprintf(":%d", s.cfg.Server.ClientPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("client API listen: %w", err)
	}
	ln = LimitListener(ln, 10000)

	if s.cfg.Server.TLS.CertFile != "" && s.cfg.Server.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("loading client TLS cert/key: %w", err)
		}
		tlsCfg := &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			Certificates:     []tls.Certificate{cert},
		}
		ln = tls.NewListener(ln, tlsCfg)
		s.logger.Info("client API listening (TLS)", "addr", addr)
	} else {
		s.logger.Warn("client API listening WITHOUT TLS — development mode only, see FR9", "addr", addr)
	}

	return s.httpServer.Serve(ln)
}

// Shutdown gracefully drains in-flight requests (NFR: graceful shutdown
// within 5s, design.md 4.10).
func (s *ClientServer) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}
