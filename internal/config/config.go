// Package config defines Sentinel's configuration schema and loads it from
// a YAML file.
//
// NOTE ON THE YAML PARSER: this build has zero external dependencies (the
// sandbox this was developed in had no network access to `go get` a real
// YAML library), so this file includes a small hand-rolled parser for the
// specific indentation-based subset of YAML that configs/sentinel.yaml
// uses: nested "key:" sections, "key: value" scalars, '#' comments, and
// optionally-quoted string values. It does NOT implement general YAML
// (no flow style, no anchors/aliases, no multi-line strings, no lists).
// If you need full YAML support, swap this for gopkg.in/yaml.v3 once you
// have network access to `go get` it — the Config struct shape will not
// need to change.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// TLSConfig holds a certificate/key pair and, for the admin API, an
// optional client CA bundle for mutual TLS.
type TLSConfig struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// ServerConfig holds listener configuration for the client and admin APIs.
type ServerConfig struct {
	ClientPort int
	AdminPort  int
	TLS        TLSConfig
	AdminTLS   TLSConfig
}

// SlidingWindowDefaults mirrors internal/window.Config in plain config
// terms (config intentionally does not import internal/window, to keep
// this package dependency-free; cmd/sentinel/main.go does the
// translation).
type SlidingWindowDefaults struct {
	Enabled        bool
	WindowDuration time.Duration
	MaxRequests    int64
	BufferSize     int
}

// BucketDefaults mirrors internal/bucket.Config in plain config terms.
type BucketDefaults struct {
	MaxTokens        int64
	RefillRate       int64
	RefillInterval   time.Duration
	TokensPerRequest int64
	SlidingWindow    *SlidingWindowDefaults
}

// Limits holds operational caps and validation bounds.
type Limits struct {
	MaxClients        int
	MaxAPIKeyLength   int
	MinRefillInterval time.Duration
	MaxRefillInterval time.Duration
}

// Security holds admin-auth and identity-extraction settings.
type Security struct {
	// AdminTokenHash/AdminTokenSalt: salted-SHA-256 bearer token for the
	// admin API (see internal/security.HashToken). Leave both empty to
	// rely solely on mTLS (Server.AdminTLS.ClientCAFile) for admin auth.
	AdminTokenHash string
	AdminTokenSalt string

	// IdentityMode: "ip" | "api_key" | "api_key_with_ip_fallback".
	IdentityMode string

	// TrustProxyHeaders: if true, honor X-Forwarded-For for source IP
	// extraction. Only enable this behind a trusted reverse proxy.
	TrustProxyHeaders bool

	EnableIPSecondaryLimit bool
	IPMaxTokens            int64
	IPRefillRate           int64
	IPRefillInterval       time.Duration
}

// Logging holds structured-logging and audit-sampling settings.
type Logging struct {
	Level             string // "debug" | "info" | "warn" | "error"
	AuditFile         string // empty = audit log goes to stdout
	RequestSampleRate float64
}

// MetricsConfig controls the Prometheus-format metrics endpoint.
type MetricsConfig struct {
	Enabled bool
	Port    int
}

// Fairness controls the advisory WFQ tracker (B4; see internal/fairness
// for the scope note on what this does and does not do).
type Fairness struct {
	Enabled       bool
	DefaultWeight float64
}

// Global controls the optional global rate limit bucket (B3).
type Global struct {
	Enabled        bool
	MaxTokens      int64
	RefillRate     int64
	RefillInterval time.Duration
}

// Config is the fully-resolved Sentinel configuration.
type Config struct {
	Server   ServerConfig
	Defaults BucketDefaults
	Limits   Limits
	Security Security
	Logging  Logging
	Metrics  MetricsConfig
	Fairness Fairness
	Global   Global
	Tiers    map[string]BucketDefaults
}

// Default returns Sentinel's built-in defaults, used when no config file
// is given/found and as the base that a config file's values are layered
// on top of.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			ClientPort: 8080,
			AdminPort:  9090,
		},
		Defaults: BucketDefaults{
			MaxTokens:        100,
			RefillRate:       10,
			RefillInterval:   time.Second,
			TokensPerRequest: 1,
		},
		Limits: Limits{
			MaxClients:        100000,
			MaxAPIKeyLength:   128,
			MinRefillInterval: 10 * time.Millisecond,
			MaxRefillInterval: time.Hour,
		},
		Security: Security{
			IdentityMode:           "api_key_with_ip_fallback",
			TrustProxyHeaders:      false,
			EnableIPSecondaryLimit: false,
			IPMaxTokens:            1000,
			IPRefillRate:           1000,
			IPRefillInterval:       time.Second,
		},
		Logging: Logging{
			Level:             "info",
			AuditFile:         "",
			RequestSampleRate: 0.01,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9100,
		},
		Fairness: Fairness{
			Enabled:       false,
			DefaultWeight: 1.0,
		},
		Global: Global{
			Enabled: false,
		},
		Tiers: map[string]BucketDefaults{},
	}
}

// node is a parsed YAML-subset tree: each value is either a string (a leaf
// scalar) or a node (a nested section).
type node map[string]interface{}

func (n node) child(key string) (node, bool) {
	v, ok := n[key]
	if !ok {
		return nil, false
	}
	c, ok := v.(node)
	return c, ok
}

func (n node) str(key, def string) string {
	s, ok := n[key].(string)
	if !ok {
		return def
	}
	return s
}

func (n node) i64(key string, def int64) int64 {
	s, ok := n[key].(string)
	if !ok {
		return def
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return def
	}
	return v
}

func (n node) i(key string, def int) int {
	return int(n.i64(key, int64(def)))
}

func (n node) f64(key string, def float64) float64 {
	s, ok := n[key].(string)
	if !ok {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

func (n node) b(key string, def bool) bool {
	s, ok := n[key].(string)
	if !ok {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return v
}

func (n node) dur(key string, def time.Duration) time.Duration {
	s, ok := n[key].(string)
	if !ok {
		return def
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return v
}

// parseTree parses a file in Sentinel's YAML subset into a node tree using
// indentation to determine nesting (spaces only; tabs are not supported).
func parseTree(path string) (node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type frame struct {
		indent int
		n      node
	}

	root := node{}
	stack := []frame{{indent: -1, n: root}}

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := leadingSpaces(line)
		trimmed := strings.TrimSpace(line)

		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			return nil, fmt.Errorf("line %d: expected 'key: value' or 'key:', got %q", lineNo, trimmed)
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		val := unquote(strings.TrimSpace(trimmed[colonIdx+1:]))

		for len(stack) > 1 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1].n

		if val == "" {
			child := node{}
			parent[key] = child
			stack = append(stack, frame{indent: indent, n: child})
		} else {
			parent[key] = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return root, nil
}

func leadingSpaces(s string) int {
	n := 0
	for _, r := range s {
		if r != ' ' {
			break
		}
		n++
	}
	return n
}

// stripComment removes a trailing '#' comment, respecting simple quoting
// so that a '#' inside a quoted string is not treated as a comment.
func stripComment(s string) string {
	inQuote := false
	var quoteChar byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = true
			quoteChar = c
			continue
		}
		if c == '#' {
			return s[:i]
		}
	}
	return s
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// parseBucketDefaults parses a "defaults:"- or "tiers.<name>:"-shaped
// section, layering onto `base` so unspecified fields inherit it.
func parseBucketDefaults(n node, base BucketDefaults) BucketDefaults {
	out := base
	out.MaxTokens = n.i64("max_tokens", base.MaxTokens)
	out.RefillRate = n.i64("refill_rate", base.RefillRate)
	out.RefillInterval = n.dur("refill_interval", base.RefillInterval)
	out.TokensPerRequest = n.i64("tokens_per_request", base.TokensPerRequest)
	if out.TokensPerRequest <= 0 {
		out.TokensPerRequest = 1
	}

	if swNode, ok := n.child("sliding_window"); ok {
		var swBase SlidingWindowDefaults
		if base.SlidingWindow != nil {
			swBase = *base.SlidingWindow
		}
		sw := SlidingWindowDefaults{
			Enabled:        swNode.b("enabled", swBase.Enabled),
			WindowDuration: swNode.dur("window_duration", swBase.WindowDuration),
			MaxRequests:    swNode.i64("max_requests", swBase.MaxRequests),
			BufferSize:     swNode.i("buffer_size", swBase.BufferSize),
		}
		out.SlidingWindow = &sw
	}
	return out
}

// Load reads and parses path into a Config, layered on top of Default().
// If path is empty, or the file does not exist, Load returns Default()
// with no error (callers should log a warning in that case if a path was
// explicitly given).
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	root, err := parseTree(path)
	if err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if n, ok := root.child("server"); ok {
		cfg.Server.ClientPort = n.i("client_port", cfg.Server.ClientPort)
		cfg.Server.AdminPort = n.i("admin_port", cfg.Server.AdminPort)
		if t, ok := n.child("tls"); ok {
			cfg.Server.TLS = TLSConfig{
				CertFile: t.str("cert_file", ""),
				KeyFile:  t.str("key_file", ""),
			}
		}
		if t, ok := n.child("admin_tls"); ok {
			cfg.Server.AdminTLS = TLSConfig{
				CertFile:     t.str("cert_file", ""),
				KeyFile:      t.str("key_file", ""),
				ClientCAFile: t.str("client_ca_file", ""),
			}
		}
	}

	if n, ok := root.child("defaults"); ok {
		cfg.Defaults = parseBucketDefaults(n, cfg.Defaults)
	}

	if n, ok := root.child("limits"); ok {
		cfg.Limits.MaxClients = n.i("max_clients", cfg.Limits.MaxClients)
		cfg.Limits.MaxAPIKeyLength = n.i("max_api_key_length", cfg.Limits.MaxAPIKeyLength)
		cfg.Limits.MinRefillInterval = n.dur("min_refill_interval", cfg.Limits.MinRefillInterval)
		cfg.Limits.MaxRefillInterval = n.dur("max_refill_interval", cfg.Limits.MaxRefillInterval)
	}

	if n, ok := root.child("security"); ok {
		cfg.Security.AdminTokenHash = n.str("admin_token_hash", cfg.Security.AdminTokenHash)
		cfg.Security.AdminTokenSalt = n.str("admin_token_salt", cfg.Security.AdminTokenSalt)
		cfg.Security.IdentityMode = n.str("identity_mode", cfg.Security.IdentityMode)
		cfg.Security.TrustProxyHeaders = n.b("trust_proxy_headers", cfg.Security.TrustProxyHeaders)
		cfg.Security.EnableIPSecondaryLimit = n.b("enable_ip_secondary_limit", cfg.Security.EnableIPSecondaryLimit)
		cfg.Security.IPMaxTokens = n.i64("ip_max_tokens", cfg.Security.IPMaxTokens)
		cfg.Security.IPRefillRate = n.i64("ip_refill_rate", cfg.Security.IPRefillRate)
		cfg.Security.IPRefillInterval = n.dur("ip_refill_interval", cfg.Security.IPRefillInterval)
	}

	if n, ok := root.child("logging"); ok {
		cfg.Logging.Level = n.str("level", cfg.Logging.Level)
		cfg.Logging.AuditFile = n.str("audit_file", cfg.Logging.AuditFile)
		cfg.Logging.RequestSampleRate = n.f64("request_sample_rate", cfg.Logging.RequestSampleRate)
	}

	if n, ok := root.child("metrics"); ok {
		cfg.Metrics.Enabled = n.b("enabled", cfg.Metrics.Enabled)
		cfg.Metrics.Port = n.i("port", cfg.Metrics.Port)
	}

	if n, ok := root.child("fairness"); ok {
		cfg.Fairness.Enabled = n.b("enabled", cfg.Fairness.Enabled)
		cfg.Fairness.DefaultWeight = n.f64("default_weight", cfg.Fairness.DefaultWeight)
	}

	if n, ok := root.child("global"); ok {
		cfg.Global.Enabled = n.b("enabled", cfg.Global.Enabled)
		cfg.Global.MaxTokens = n.i64("max_tokens", cfg.Global.MaxTokens)
		cfg.Global.RefillRate = n.i64("refill_rate", cfg.Global.RefillRate)
		cfg.Global.RefillInterval = n.dur("refill_interval", cfg.Global.RefillInterval)
	}

	if n, ok := root.child("tiers"); ok {
		for tierName, v := range n {
			tn, ok := v.(node)
			if !ok {
				continue
			}
			cfg.Tiers[tierName] = parseBucketDefaults(tn, cfg.Defaults)
		}
	}

	return cfg, nil
}

// Validate sanity-checks a loaded Config and returns a descriptive error
// for the first problem found.
func (c *Config) Validate() error {
	if c.Server.ClientPort <= 0 || c.Server.ClientPort > 65535 {
		return fmt.Errorf("server.client_port out of range: %d", c.Server.ClientPort)
	}
	if c.Server.AdminPort <= 0 || c.Server.AdminPort > 65535 {
		return fmt.Errorf("server.admin_port out of range: %d", c.Server.AdminPort)
	}
	if c.Server.ClientPort == c.Server.AdminPort {
		return fmt.Errorf("server.client_port and server.admin_port must differ")
	}
	if c.Metrics.Enabled {
		if c.Metrics.Port <= 0 || c.Metrics.Port > 65535 {
			return fmt.Errorf("metrics.port out of range: %d", c.Metrics.Port)
		}
		if c.Metrics.Port == c.Server.ClientPort || c.Metrics.Port == c.Server.AdminPort {
			return fmt.Errorf("metrics.port must differ from client_port/admin_port")
		}
	}
	if c.Defaults.MaxTokens <= 0 {
		return fmt.Errorf("defaults.max_tokens must be positive")
	}
	if c.Defaults.RefillRate < 0 {
		return fmt.Errorf("defaults.refill_rate must not be negative")
	}
	if c.Limits.MaxClients <= 0 {
		return fmt.Errorf("limits.max_clients must be positive")
	}
	if c.Logging.RequestSampleRate < 0 || c.Logging.RequestSampleRate > 1 {
		return fmt.Errorf("logging.request_sample_rate must be within [0,1], got %v", c.Logging.RequestSampleRate)
	}
	switch c.Security.IdentityMode {
	case "ip", "api_key", "api_key_with_ip_fallback":
	default:
		return fmt.Errorf("security.identity_mode invalid: %q (want ip|api_key|api_key_with_ip_fallback)", c.Security.IdentityMode)
	}
	if c.Fairness.Enabled && c.Fairness.DefaultWeight <= 0 {
		return fmt.Errorf("fairness.default_weight must be positive when fairness is enabled")
	}
	if c.Global.Enabled && c.Global.MaxTokens <= 0 {
		return fmt.Errorf("global.max_tokens must be positive when global limiting is enabled")
	}
	return nil
}
