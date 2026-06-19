package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return path
}

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got: %v", err)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	def := Default()
	if cfg.Server.ClientPort != def.Server.ClientPort {
		t.Fatalf("expected default client port, got %d", cfg.Server.ClientPort)
	}
}

func TestLoadParsesNestedSections(t *testing.T) {
	yaml := `
server:
  client_port: 9001
  admin_port: 9002
  tls:
    cert_file: certs/server.crt
    key_file: certs/server.key

defaults:
  max_tokens: 250
  refill_rate: 25
  refill_interval: 2s
  sliding_window:
    enabled: true
    window_duration: 10s
    max_requests: 30
    buffer_size: 31

limits:
  max_clients: 5000

security:
  identity_mode: ip
  enable_ip_secondary_limit: true
  ip_max_tokens: 50

logging:
  level: debug
  request_sample_rate: 0.5

global:
  enabled: true
  max_tokens: 1000
  refill_rate: 100
  refill_interval: 1s

tiers:
  read:
    max_tokens: 500
    refill_rate: 50
    refill_interval: 1s
  write:
    max_tokens: 20
    refill_rate: 5
    refill_interval: 1s
`
	path := writeTempConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if cfg.Server.ClientPort != 9001 || cfg.Server.AdminPort != 9002 {
		t.Fatalf("unexpected server ports: %+v", cfg.Server)
	}
	if cfg.Server.TLS.CertFile != "certs/server.crt" {
		t.Fatalf("unexpected TLS cert file: %q", cfg.Server.TLS.CertFile)
	}
	if cfg.Defaults.MaxTokens != 250 || cfg.Defaults.RefillRate != 25 {
		t.Fatalf("unexpected defaults: %+v", cfg.Defaults)
	}
	if cfg.Defaults.RefillInterval != 2*time.Second {
		t.Fatalf("unexpected refill interval: %v", cfg.Defaults.RefillInterval)
	}
	if cfg.Defaults.SlidingWindow == nil || !cfg.Defaults.SlidingWindow.Enabled {
		t.Fatalf("expected sliding window enabled")
	}
	if cfg.Defaults.SlidingWindow.MaxRequests != 30 {
		t.Fatalf("unexpected sliding window max_requests: %d", cfg.Defaults.SlidingWindow.MaxRequests)
	}
	if cfg.Limits.MaxClients != 5000 {
		t.Fatalf("unexpected max_clients: %d", cfg.Limits.MaxClients)
	}
	if cfg.Security.IdentityMode != "ip" || !cfg.Security.EnableIPSecondaryLimit {
		t.Fatalf("unexpected security: %+v", cfg.Security)
	}
	if cfg.Logging.Level != "debug" || cfg.Logging.RequestSampleRate != 0.5 {
		t.Fatalf("unexpected logging: %+v", cfg.Logging)
	}
	if !cfg.Global.Enabled || cfg.Global.MaxTokens != 1000 {
		t.Fatalf("unexpected global: %+v", cfg.Global)
	}
	if len(cfg.Tiers) != 2 {
		t.Fatalf("expected 2 tiers, got %d", len(cfg.Tiers))
	}
	if cfg.Tiers["read"].MaxTokens != 500 {
		t.Fatalf("unexpected read tier max_tokens: %d", cfg.Tiers["read"].MaxTokens)
	}
}

func TestLoadIgnoresComments(t *testing.T) {
	yaml := `
# top level comment
server:
  client_port: 9001 # inline comment
  admin_port: 9002
`
	path := writeTempConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.ClientPort != 9001 {
		t.Fatalf("expected inline-comment-stripped port 9001, got %d", cfg.Server.ClientPort)
	}
}

func TestValidateRejectsSamePorts(t *testing.T) {
	cfg := Default()
	cfg.Server.AdminPort = cfg.Server.ClientPort
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for identical client/admin ports")
	}
}

func TestValidateRejectsBadIdentityMode(t *testing.T) {
	cfg := Default()
	cfg.Security.IdentityMode = "nonsense"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for bad identity mode")
	}
}

func TestValidateRejectsOutOfRangeSampleRate(t *testing.T) {
	cfg := Default()
	cfg.Logging.RequestSampleRate = 1.5
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for sample rate > 1")
	}
}
