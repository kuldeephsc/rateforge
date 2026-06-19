// Package audit implements Sentinel's audit logging policy (FR... / design
// section "Audit & Logging"): rejected requests and all admin changes are
// always logged; allowed requests are sampled to bound log volume at high
// throughput.
package audit

import (
	"log/slog"
	"math/rand"
	"time"
)

// Logger wraps a base structured logger with Sentinel's audit-specific
// sampling policy.
type Logger struct {
	base       *slog.Logger
	sampleRate float64
}

// New creates an audit Logger. sampleRate is clamped to [0, 1] and
// controls what fraction of *allowed* decisions are logged (rejections
// and admin changes are always logged regardless of sampleRate).
func New(base *slog.Logger, sampleRate float64) *Logger {
	if sampleRate < 0 {
		sampleRate = 0
	}
	if sampleRate > 1 {
		sampleRate = 1
	}
	return &Logger{base: base, sampleRate: sampleRate}
}

// RequestDecision logs one rate-limit decision. Rejections are always
// logged at Warn; allowed decisions are sampled at Debug per sampleRate.
func (l *Logger) RequestDecision(allowed bool, clientKey, sourceIP string, remaining int64, latency time.Duration) {
	if l == nil || l.base == nil {
		return
	}

	if !allowed {
		l.base.Warn("request_decision",
			"allowed", allowed,
			"client_key", clientKey,
			"source_ip", sourceIP,
			"tokens_remaining", remaining,
			"latency_us", latency.Microseconds(),
		)
		return
	}

	if l.sampleRate <= 0 {
		return
	}
	if l.sampleRate < 1 && rand.Float64() >= l.sampleRate {
		return
	}

	l.base.Debug("request_decision",
		"allowed", allowed,
		"client_key", clientKey,
		"source_ip", sourceIP,
		"tokens_remaining", remaining,
		"latency_us", latency.Microseconds(),
	)
}

// AdminChange logs an administrative mutation. Always logged at Info,
// regardless of sampling, with before/after state for auditability.
func (l *Logger) AdminChange(admin, clientKey, action string, before, after any, sourceIP string) {
	if l == nil || l.base == nil {
		return
	}
	l.base.Info("admin_change",
		"admin", admin,
		"client_key", clientKey,
		"action", action,
		"before", before,
		"after", after,
		"source_ip", sourceIP,
	)
}

// Anomaly logs a security-relevant anomaly (e.g. failed admin auth,
// malformed input rejected before reaching business logic). Always logged
// at Warn.
func (l *Logger) Anomaly(kind, detail, sourceIP string) {
	if l == nil || l.base == nil {
		return
	}
	l.base.Warn("anomaly", "kind", kind, "detail", detail, "source_ip", sourceIP)
}
