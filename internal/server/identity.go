package server

import (
	"net"
	"net/http"
	"strings"
)

// sourceIP extracts the caller's IP address from r. If trustProxy is true,
// X-Forwarded-For (first hop) or X-Real-IP are honored; this must only be
// enabled when Sentinel sits behind a trusted reverse proxy that strips/
// overwrites these headers from untrusted clients, otherwise a client can
// trivially spoof its IP and evade the per-IP secondary limit (B5).
func sourceIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			return xrip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIdentity derives the rate-limiting identity for a request per
// FR5/Security.IdentityMode: prefer X-API-Key, with optional IP fallback.
// usedFallback is true when the IP was used because no API key was
// presented (informational only; both paths are validated identically).
func clientIdentity(r *http.Request, ip, mode string) (key string, usedFallback bool) {
	apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	switch mode {
	case "ip":
		return ip, true
	case "api_key":
		return apiKey, false
	default: // "api_key_with_ip_fallback"
		if apiKey != "" {
			return apiKey, false
		}
		return ip, true
	}
}
