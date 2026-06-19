# RateForge | Event-Driven Rate Limiting & Traffic Governance Platform

A single-node rate-limiting & scheduling service in Go: per-client token
buckets with an event-driven min-heap refill scheduler, a separate admin
API for hot configuration, and the full bonus feature set from the
original design (sliding window, multi-tier buckets, a global limit,
per-IP anti-evasion, and an advisory fairness tracker).

See [`design.md`](./design.md) for the full PRD, threat model, HLD, and LLD
this implementation follows. The few places this build intentionally
diverges from that document are called out in
[Deviations from design.md](#deviations-from-designmd) below — all in one
direction: trading a third-party dependency for a small hand-rolled
equivalent, because the environment this was built in had no network
access to `go get` anything. **The result is a single Go module with zero
external dependencies** (`go.mod` imports nothing but the standard
library), which also means there's no `go mod download` step, no
supply-chain surface to audit, and one less thing that can break a build.

## Project layout

```
RateForge | Event-Driven Rate Limiting & Traffic Governance Platform/
├── cmd/
│   ├── RateForge | Event-Driven Rate Limiting & Traffic Governance Platform/        # main service binary
│   └── simulator/       # traffic-generator CLI (FR6)
├── internal/
│   ├── bucket/          # token bucket: lock-free hot path (atomics + CAS)
│   ├── window/          # sliding-window secondary limiter (B1)
│   ├── multibucket/     # per-client multi-tier buckets (B2)
│   ├── fairness/        # advisory WFQ tracker (B4)
│   ├── scheduler/        # event-driven min-heap refill scheduler (FR3/FR4)
│   ├── store/            # BucketStore: client map, LRU, global+IP buckets
│   ├── security/         # input validation, constant-time compare
│   ├── audit/             # sampled/always-on structured audit logging
│   ├── metrics/           # zero-dependency Prometheus-format registry
│   ├── config/            # config schema + hand-rolled YAML-subset loader
│   └── server/             # client API, admin API, shared middleware
├── configs/RateForge | Event-Driven Rate Limiting & Traffic Governance Platform.yaml
├── scripts/gen_certs.sh    # local dev PKI for TLS/mTLS testing
├── Dockerfile               # distroless, non-root (B6)
└── Makefile
```

## Build & run

Requires Go 1.22+ (the admin/client routers use 1.22's method+wildcard
`http.ServeMux` patterns) and nothing else — no `go mod download` needed.

```bash
# 1. (optional) generate local dev certs for TLS/mTLS
make certs

# 2. build both binaries into ./bin
make build

# 3. run the service
./bin/RateForge | Event-Driven Rate Limiting & Traffic Governance Platform --config configs/RateForge | Event-Driven Rate Limiting & Traffic Governance Platform.yaml
```

Without certs in `configs/RateForge | Event-Driven Rate Limiting & Traffic Governance Platform.yaml`'s `server.tls`/`server.admin_tls`
sections, both APIs fall back to plain HTTP and log a loud startup
warning — convenient for local iteration, never for production (FR9).

Run the test suite:

```bash
make test        # go test ./...
make test-race   # go test -race ./...   (validates the lock-free Bucket path)
```

Run the traffic simulator against a running instance (FR6):

```bash
./bin/simulator --server https://localhost:8080 \
  --clients 50 --rps 20 --burst 10 --duration 30s --jitter 10ms
```

Build & run in Docker (B6):

```bash
make docker
docker run -p 8080:8080 -p 9090:9090 -p 9100:9100 RateForge | Event-Driven Rate Limiting & Traffic Governance Platform:latest
```

## API

### Client API (`server.client_port`, default 8080)

| Method | Path | Headers | Response |
|---|---|---|---|
| `POST` | `/api/v1/request` | `X-API-Key`, optional `X-Resource-Tier` | `200 {"allowed":true,"remaining_tokens":N}` or `429 {"allowed":false,"retry_after_ms":N,"reset_at":"..."}` + `Retry-After` header |
| `GET` | `/healthz` | — | `200` |

```bash
curl -i -X POST https://localhost:8080/api/v1/request -H "X-API-Key: abc123" -k
```

### Admin API (`server.admin_port`, default 9090)

All endpoints require either a verified mTLS client cert (if
`server.admin_tls.client_ca_file` is set) and/or a bearer token (if
`security.admin_token_hash` is set). If neither is configured, the admin
API is unauthenticated and a startup warning is logged — set at least one
before exposing it beyond localhost.

| Method | Path | Body | Description |
|---|---|---|---|
| `PUT` | `/admin/v1/clients/{key}/config` | `{"tier":"","max_tokens":200,"refill_rate":20,"refill_interval_ms":1000}` | Merge-patch update; omitted fields keep their current value. |
| `PUT` | `/admin/v1/clients/{key}/block` | — | Block immediately. |
| `PUT` | `/admin/v1/clients/{key}/unblock` | — | Unblock. |
| `GET` | `/admin/v1/clients/{key}/status` | — | Current tokens, config, blocked state per tier. |
| `GET` | `/admin/v1/clients` | — | Status for every tracked client. |
| `PUT` | `/admin/v1/global/config` | `{"enabled":true,"max_tokens":5000,"refill_rate":1000,"refill_interval_ms":1000}` | Global rate limit (B3). |
| `GET` | `/admin/v1/fairness` | — | WFQ tracker snapshot (B4, observability only — see scope note in `internal/fairness`). |

```bash
curl -i -X PUT https://localhost:9090/admin/v1/clients/abc123/config \
  -H "Authorization: Bearer <token>" \
  -d '{"max_tokens":200,"refill_rate":20,"refill_interval_ms":1000}' -k
```

To generate an `admin_token_hash`/`admin_token_salt` pair for
`configs/RateForge | Event-Driven Rate Limiting & Traffic Governance Platform.yaml`:

```go
package main

import "RateForge | Event-Driven Rate Limiting & Traffic Governance Platform/internal/security"

func main() {
    salt := "some-random-salt"
    token := "your-long-random-admin-token"
    println(security.HashToken(token, salt))
}
```

### Metrics (`metrics.port`, default 9100)

`GET /metrics` in Prometheus text exposition format:
`RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_requests_total{decision="allow|reject|blocked"}`,
`RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_request_latency_seconds`, `RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_active_clients`,
`RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_scheduler_refills_total`, `RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_scheduler_heap_size`,
`RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_evictions_total`, `RateForge | Event-Driven Rate Limiting & Traffic Governance Platform_admin_changes_total{action=...}`.

## Deviations from design.md

The design document's architecture, data structures, concurrency model,
threat model, and API surface are implemented as specified. Three pieces
of the LLD named specific third-party packages that were unreachable in
the sandbox this was built in (no network access to `go get`); each was
replaced with a small, clearly-documented, zero-dependency equivalent
rather than left unimplemented:

| design.md said | This build uses | Why / where documented |
|---|---|---|
| `gopkg.in/yaml.v3` for config | A ~150-line hand-rolled parser for the indentation-based subset of YAML `configs/RateForge | Event-Driven Rate Limiting & Traffic Governance Platform.yaml` actually uses (nested sections, scalars, comments, quoting — no flow style/anchors/lists) | `internal/config/config.go` package doc |
| `github.com/prometheus/client_golang` for metrics | A hand-rolled registry emitting the same Prometheus text exposition format (counters, gauges, fixed-bucket histograms) | `internal/metrics/metrics.go` package doc |
| bcrypt for admin token storage (D8) | Salted SHA-256 + `crypto/subtle` constant-time comparison | `internal/security/sanitize.go`, `HashToken` doc comment — explicitly flagged as appropriate *only* because admin bearer tokens are long random secrets, not human passwords; swap to bcrypt/argon2id (`golang.org/x/crypto`) if that assumption ever changes |

`golang.org/x/net/netutil.LimitListener` was similarly unavailable; a
~20-line equivalent lives in `internal/server/middleware.go`.

None of these change the public API, the data structures, or the
concurrency design described in `design.md` — only the implementation of
three leaf-level concerns. The `Config` struct's shape, the metrics
names/types, and the admin auth flow are exactly as specified.

## Known limitation: fairness scheduling (B4)

`internal/fairness.Tracker` faithfully implements the spec's
virtual-finish-time bookkeeping and exposes it at `GET
/admin/v1/fairness`, but Go's `net/http` hands each request its own
goroutine with no central admission queue — so there is currently no
mechanism in this build that actually reorders or delays requests based on
that bookkeeping. This is called out in the package doc comment; wiring
it into request ordering would mean adding a bespoke admission-queue layer
in front of `net/http`, which was treated as out of scope for the time
available.
