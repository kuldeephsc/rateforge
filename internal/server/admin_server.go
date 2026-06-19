// AdminServer implements the admin API (FR7): hot-reload client config,
// block/unblock, status, and the bonus global-limit/fairness endpoints —
// all on a separate port from the client API (D3), guarded by mTLS and/or
// a bearer token (FR9, T4).
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/bucket"
	"sentinel/internal/config"
	"sentinel/internal/fairness"
	"sentinel/internal/metrics"
	"sentinel/internal/security"
	"sentinel/internal/store"
)

// AdminServer wires the BucketStore up to an HTTP listener for the admin
// API.
type AdminServer struct {
	cfg      *config.Config
	store    *store.BucketStore
	fairness *fairness.Tracker
	audit    *audit.Logger
	metrics  *metrics.Registry
	logger   *slog.Logger

	httpServer *http.Server
}

// NewAdminServer constructs an AdminServer. Call ListenAndServe to start
// it (typically in its own goroutine).
func NewAdminServer(cfg *config.Config, st *store.BucketStore, ft *fairness.Tracker, al *audit.Logger, reg *metrics.Registry, logger *slog.Logger) *AdminServer {
	return &AdminServer{cfg: cfg, store: st, fairness: ft, audit: al, metrics: reg, logger: logger}
}

// --- request/response bodies -----------------------------------------

// maxAdminBodyBytes enforces design.md 4.5: admin request bodies are
// capped at 1 KB.
const maxAdminBodyBytes = 1024

type updateConfigRequest struct {
	Tier             string `json:"tier"`
	MaxTokens        *int64 `json:"max_tokens"`
	RefillRate       *int64 `json:"refill_rate"`
	RefillIntervalMs *int64 `json:"refill_interval_ms"`
}

type configSnapshot struct {
	MaxTokens        int64 `json:"max_tokens"`
	RefillRate       int64 `json:"refill_rate"`
	RefillIntervalMs int64 `json:"refill_interval_ms"`
}

func snapshot(cfg bucket.Config) configSnapshot {
	return configSnapshot{
		MaxTokens:        cfg.MaxTokens,
		RefillRate:       cfg.RefillRate,
		RefillIntervalMs: cfg.RefillInterval.Milliseconds(),
	}
}

type globalConfigRequest struct {
	Enabled          bool  `json:"enabled"`
	MaxTokens        int64 `json:"max_tokens"`
	RefillRate       int64 `json:"refill_rate"`
	RefillIntervalMs int64 `json:"refill_interval_ms"`
}

// readAdminBody enforces the size cap and decodes JSON, rejecting unknown
// fields to reduce ambiguity about what was actually applied.
func readAdminBody(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("empty body")
	}
	limited := io.LimitReader(r.Body, maxAdminBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxAdminBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxAdminBodyBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- handlers -----------------------------------------------------------

func (s *AdminServer) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := security.ValidateAPIKey(key); err != nil {
		writeError(w, http.StatusBadRequest, "invalid client key")
		return
	}

	var req updateConfigRequest
	if err := readAdminBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := security.ValidateTier(req.Tier); err != nil {
		writeError(w, http.StatusBadRequest, "invalid tier")
		return
	}

	now := time.Now()
	before := s.store.TierConfig(key, req.Tier)
	after := before
	if req.MaxTokens != nil {
		after.MaxTokens = *req.MaxTokens
	}
	if req.RefillRate != nil {
		after.RefillRate = *req.RefillRate
	}
	if req.RefillIntervalMs != nil {
		after.RefillInterval = time.Duration(*req.RefillIntervalMs) * time.Millisecond
	}
	if after.TokensPerRequest <= 0 {
		after.TokensPerRequest = 1
	}

	if err := security.ValidateBucketConfig(after.MaxTokens, after.RefillRate, after.RefillInterval); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if after.RefillInterval < s.cfg.Limits.MinRefillInterval || after.RefillInterval > s.cfg.Limits.MaxRefillInterval {
		writeError(w, http.StatusBadRequest, "refill_interval out of configured bounds")
		return
	}

	s.store.UpdateClientConfig(key, req.Tier, after, now)

	s.audit.AdminChange(adminIdentity(r), key, "update_config", snapshot(before), snapshot(after), sourceIP(r, s.cfg.Security.TrustProxyHeaders))
	if s.metrics != nil {
		s.metrics.AdminChangesTotal.Inc("update_config")
	}

	writeJSON(w, http.StatusOK, snapshot(after))
}

func (s *AdminServer) handleBlock(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := security.ValidateAPIKey(key); err != nil {
		writeError(w, http.StatusBadRequest, "invalid client key")
		return
	}
	s.store.Block(key, time.Now())
	s.audit.AdminChange(adminIdentity(r), key, "block", nil, nil, sourceIP(r, s.cfg.Security.TrustProxyHeaders))
	if s.metrics != nil {
		s.metrics.AdminChangesTotal.Inc("block")
	}
	w.WriteHeader(http.StatusOK)
}

func (s *AdminServer) handleUnblock(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := security.ValidateAPIKey(key); err != nil {
		writeError(w, http.StatusBadRequest, "invalid client key")
		return
	}
	s.store.Unblock(key)
	s.audit.AdminChange(adminIdentity(r), key, "unblock", nil, nil, sourceIP(r, s.cfg.Security.TrustProxyHeaders))
	if s.metrics != nil {
		s.metrics.AdminChangesTotal.Inc("unblock")
	}
	w.WriteHeader(http.StatusOK)
}

func (s *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	status, ok := s.store.Status(key)
	if !ok {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *AdminServer) handleListClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListClients())
}

func (s *AdminServer) handleGlobalConfig(w http.ResponseWriter, r *http.Request) {
	var req globalConfigRequest
	if err := readAdminBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !req.Enabled {
		s.store.DisableGlobal()
		s.audit.AdminChange(adminIdentity(r), "__global__", "disable_global", nil, nil, sourceIP(r, s.cfg.Security.TrustProxyHeaders))
		if s.metrics != nil {
			s.metrics.AdminChangesTotal.Inc("disable_global")
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	interval := time.Duration(req.RefillIntervalMs) * time.Millisecond
	if err := security.ValidateBucketConfig(req.MaxTokens, req.RefillRate, interval); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg := bucket.Config{MaxTokens: req.MaxTokens, RefillRate: req.RefillRate, RefillInterval: interval, TokensPerRequest: 1}
	s.store.SetGlobalConfig(cfg, time.Now())
	s.audit.AdminChange(adminIdentity(r), "__global__", "set_global_config", nil, snapshot(cfg), sourceIP(r, s.cfg.Security.TrustProxyHeaders))
	if s.metrics != nil {
		s.metrics.AdminChangesTotal.Inc("set_global_config")
	}
	writeJSON(w, http.StatusOK, snapshot(cfg))
}

// handleFairness exposes the WFQ tracker's bookkeeping for observability
// (B4). See internal/fairness's package doc for the scope note on what
// this tracker does and does not influence.
func (s *AdminServer) handleFairness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     s.fairness.Enabled(),
		"consumption": s.fairness.Snapshot(),
	})
}

// adminIdentity returns a label for the audit log identifying which admin
// credential made the change, without ever logging the credential itself.
func adminIdentity(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return "mtls:" + r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return "bearer-token"
}

// --- auth middleware & lifecycle ----------------------------------------

// authMiddleware enforces FR9/T4: if an admin bearer token hash is
// configured, every request must present a matching token, compared in
// constant time. If no token is configured, auth relies solely on mTLS
// (Server.AdminTLS.ClientCAFile) having already been enforced at the TLS
// layer before the request reaches here.
func (s *AdminServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Security.AdminTokenHash == "" {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, prefix) {
			s.audit.Anomaly("admin_auth_missing", "", sourceIP(r, s.cfg.Security.TrustProxyHeaders))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authz, prefix)
		hash := security.HashToken(token, s.cfg.Security.AdminTokenSalt)
		if !security.ConstantTimeEqual(hash, s.cfg.Security.AdminTokenHash) {
			s.audit.Anomaly("admin_auth_failed", "", sourceIP(r, s.cfg.Security.TrustProxyHeaders))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the admin API listener with mTLS (if a client CA
// is configured) and/or bearer-token auth, and blocks serving until
// Shutdown is called.
func (s *AdminServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /admin/v1/clients/{key}/config", s.handleUpdateConfig)
	mux.HandleFunc("PUT /admin/v1/clients/{key}/block", s.handleBlock)
	mux.HandleFunc("PUT /admin/v1/clients/{key}/unblock", s.handleUnblock)
	mux.HandleFunc("GET /admin/v1/clients/{key}/status", s.handleStatus)
	mux.HandleFunc("GET /admin/v1/clients", s.handleListClients)
	mux.HandleFunc("PUT /admin/v1/global/config", s.handleGlobalConfig)
	mux.HandleFunc("GET /admin/v1/fairness", s.handleFairness)

	handler := RecoverMiddleware(s.logger, s.authMiddleware(mux))

	s.httpServer = &http.Server{
		Handler:        handler,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 4 << 10,
	}

	addr := fmt.Sprintf(":%d", s.cfg.Server.AdminPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin API listen: %w", err)
	}
	ln = LimitListener(ln, 1000)

	if s.cfg.Server.AdminTLS.CertFile != "" && s.cfg.Server.AdminTLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.Server.AdminTLS.CertFile, s.cfg.Server.AdminTLS.KeyFile)
		if err != nil {
			return fmt.Errorf("loading admin TLS cert/key: %w", err)
		}
		tlsCfg := &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			Certificates:     []tls.Certificate{cert},
		}
		if s.cfg.Server.AdminTLS.ClientCAFile != "" {
			caPEM, err := os.ReadFile(s.cfg.Server.AdminTLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("reading admin client CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return fmt.Errorf("admin client CA file contains no valid certificates")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			s.logger.Info("admin API listening (mTLS)", "addr", addr)
		} else {
			s.logger.Info("admin API listening (TLS, bearer-token auth)", "addr", addr)
		}
		ln = tls.NewListener(ln, tlsCfg)
	} else {
		s.logger.Warn("admin API listening WITHOUT TLS — development mode only, see FR9/T4", "addr", addr)
	}

	if s.cfg.Server.AdminTLS.ClientCAFile == "" && s.cfg.Security.AdminTokenHash == "" {
		s.logger.Warn("admin API has NEITHER mTLS NOR a bearer token configured — all requests are unauthenticated")
	}

	return s.httpServer.Serve(ln)
}

// Shutdown gracefully drains in-flight requests.
func (s *AdminServer) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}
