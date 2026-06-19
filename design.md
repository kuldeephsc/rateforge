# RateForge(Sentinel) | Event-Driven Rate Limiting & Traffic Governance Platform

> **Language:** Go 1.22+ | **Status:** FINAL | **Date:** 2026-02-10

---

## 1. Product Requirements Document (PRD)

### 1.1 Problem Statement

A single-node rate-limiting service that enforces per-client request limits using a Token Bucket algorithm, with efficient refill scheduling via a Min-Heap. Architecturally aware of distributed deployment (state partitioning, clock drift) but runs locally. Clients are simulated via concurrent goroutines.

### 1.2 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR1 | Per-client token bucket with configurable burst capacity (`MaxTokens`), `RefillRate`, and `RefillInterval`. | P0 |
| FR2 | Each request checks token availability; allowed → 200, rejected → 429 + `Retry-After`. | P0 |
| FR3 | Min-Heap scheduler: only the bucket due next is processed — O(log n) insert/extract, O(1) peek. | P0 |
| FR4 | Hybrid refill: lazy refill on request (correctness) + scheduled refill via heap (efficiency). | P0 |
| FR5 | Client identity via `X-API-Key` header; fallback to source IP (configurable). | P0 |
| FR6 | Traffic simulator: N goroutines, configurable RPS, burst, duration, jitter per client. | P0 |
| FR7 | Admin API (separate port): update config, block/unblock client, get status — hot reload, no restart. | P0 |
| FR8 | Structured JSON logging (`slog`): request decisions (sampled), admin changes (always), anomalies. | P0 |
| FR9 | TLS for client API; mTLS or bearer-token auth for admin API. | P0 |
| FR10 | LRU eviction when client count exceeds configurable cap (memory protection). | P0 |
| B1 | Sliding-window rate limiting (ring buffer of timestamps). | Bonus |
| B2 | Multi-bucket per client (default / expensive / burst tiers via `X-Resource-Tier`). | Bonus |
| B3 | Global rate limit bucket shared across all clients. | Bonus |
| B4 | Fairness scheduling (weighted fair queue by remaining token ratio). | Bonus |
| B5 | Anti-evasion: per-IP secondary limit to catch key rotation abuse. | Bonus |
| B6 | Containerization (Dockerfile, distroless image, non-root). | Bonus |

### 1.3 Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Decision latency | < 50 µs p99 (in-memory) |
| Throughput | > 100K decisions/sec single-core |
| Memory per bucket | < 256 bytes |
| Scheduler wake-ups | Event-driven via heap, no polling |
| Graceful shutdown | Drain in-flight within 5 s |

### 1.4 Non-Goals

- Real multi-machine deployment (simulated locally).
- Persistent storage (in-memory; restart resets state).
- Full API gateway features (routing, payload transformation).

---

## 2. SSDLC & Threat Model

### 2.1 Secure Development Lifecycle

| Phase | Activity |
|-------|----------|
| **Requirements** | Threat model, abuse-case analysis, security requirements (this section). |
| **Design** | Secure-by-design principles, least privilege, defense-in-depth, fail-closed. |
| **Implementation** | Input validation, safe concurrency (atomics + mutex), no data races, dependency scanning. |
| **Testing** | Fuzz testing (bucket + admin API), race detector (`-race`), negative tests, SAST. |
| **Deployment** | Distroless container, non-root, read-only FS, resource limits. |
| **Operations** | Structured audit logs, Prometheus metrics, anomaly alerting. |

### 2.2 Secure-by-Design Principles

1. **Least Privilege** — Service runs non-root. Admin API requires separate credentials. API keys grant only request submission.
2. **Defense in Depth** — Per-key limit + per-IP secondary limit + global limit = three layers.
3. **Fail Closed** — Internal error (panic, heap corruption) → reject by default.
4. **Input Validation** — API keys: `^[a-zA-Z0-9_-]{1,128}$`. Config values: bounded ranges. Request body: max 1 KB (admin), none (client).
5. **Immutable Audit** — Admin changes logged append-only with before/after diffs.
6. **Minimal Surface** — Two ports only (client + admin). No debug/reflection endpoints in production.

### 2.3 Threat Matrix (STRIDE)

| # | Threat | Category | Impact | Mitigation |
|---|--------|----------|--------|------------|
| T1 | Flood requests to exhaust rate-limiter CPU/memory | DoS | High | Global rate limit; connection limits; per-IP pre-filter. |
| T2 | Rotate API keys to evade per-key limits | Evasion | High | Per-IP secondary limit; new-key creation rate cap; anomaly detection. |
| T3 | Replay valid API key | Spoofing | Medium | TLS in transit; optional HMAC-signed timestamps (30 s replay window). |
| T4 | Unauthorized admin API access | Elevation | Critical | Separate port; mTLS or bearer token (bcrypt-hashed); IP allowlist. |
| T5 | Unbounded bucket creation → OOM | DoS | High | Max client cap (default 100K); LRU eviction of idle buckets. |
| T6 | Race condition in token decrement | Tampering | Medium | `atomic.Int64` + CAS loop; `-race` in CI. |
| T7 | Log injection via crafted API key | Tampering | Low | Structured logging (key-value, no interpolation); input sanitization. |
| T8 | Heap corruption → stale refills | Integrity | Medium | Heap validation on push/pop; lazy refill as fallback correctness. |

### 2.4 Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│              UNTRUSTED ZONE                     │
│  Simulated Clients (API keys, HTTP requests)    │
└──────────────┬──────────────────────────────────┘
               │ TLS (port 8080)
               ▼
┌─────────────────────────────────────────────────┐
│         SENTINEL SERVICE                        │
│  ┌────────────┐ ┌───────────┐ ┌──────────────┐  │
│  │ ClientAPI  │→│ BucketStore│→│ Scheduler    │  │
│  │ (validate) │ │ (map+LRU) │ │ (min-heap)   │  │
│  └────────────┘ └───────────┘ └──────────────┘  │
│  ┌────────────┐ ┌──────────────────────────┐     │
│  │ AdminAPI   │ │ AuditLogger (append-only)│     │
│  └─────┬──────┘ └──────────────────────────┘     │
│        │ mTLS/Bearer (port 9090)                 │
└────────┼────────────────────────────────────────┘
         ▼
┌─────────────────────────────────────────────────┐
│              TRUSTED ZONE                       │
│     Admin CLI (authenticated operator)          │
└─────────────────────────────────────────────────┘
```

---

## 3. High-Level Design (HLD)

### 3.1 Architecture

```
                      ┌────────────────────────────────────────┐
                      │        sentinel (single binary)        │
                      │                                        │
 Clients ─TLS:8080─►  │  ┌──────────┐   ┌─────────────────┐   │
                      │  │ClientAPI │──►│  BucketStore    │   │
                      │  │(HTTP)    │   │  map[key]*Bucket│   │
                      │  └──────────┘   └────────┬────────┘   │
                      │                          │            │
                      │                          ▼            │
                      │                 ┌─────────────────┐   │
                      │                 │RefillScheduler  │   │
                      │                 │(min-heap)       │   │
                      │                 └─────────────────┘   │
                      │                                        │
 Admin ─mTLS:9090──►  │  ┌──────────┐   ┌─────────────────┐   │
                      │  │AdminAPI  │──►│ AuditLogger     │   │
                      │  │(HTTP)    │   │ (slog + file)   │   │
                      │  └──────────┘   └─────────────────┘   │
                      │                                        │
                      │  ┌──────────────────────────────────┐  │
                      │  │ Prometheus Metrics (:9100)       │  │
                      │  └──────────────────────────────────┘  │
                      └────────────────────────────────────────┘
```

### 3.2 Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| **ClientServer** | Accept requests over TLS. Extract client key from `X-API-Key` (or IP fallback). Call `BucketStore.Allow()`. Return 200 or 429 + `Retry-After`. |
| **AdminServer** | Accept admin commands over mTLS/bearer on separate port. Validate credentials. Mutate configs, block/unblock. Emit audit entries. |
| **BucketStore** | Thread-safe `map[string]*Bucket`. Lazy refill on access. LRU eviction at capacity. Creates bucket on first request or admin provisioning. |
| **Bucket** | Token state: atomic `tokens`, `maxTokens`, `refillRate`, `refillInterval`, `lastRefillTime`, `blocked`. Provides `Allow(n)` and `Refill()`. |
| **RefillScheduler** | Dedicated goroutine. Min-heap of `(nextRefillTime, clientKey)`. Sleeps until earliest, batch-refills due buckets, re-inserts. `Reschedule()` for live config changes. |
| **AuditLogger** | Wraps `slog.Logger`. Structured JSON. Admin diffs always logged. Request decisions sampled at configurable rate. All 429s logged. |
| **TrafficSimulator** | Separate binary (`cmd/simulator`). N goroutines with configurable RPS/burst/duration/jitter. Reports per-client stats. |

### 3.3 Request Flow — Allowed

```
Client              ClientServer          BucketStore           Bucket
  │─ POST /api/v1/request ─►│                    │                  │
  │  X-API-Key: abc123       │─ Allow("abc123",1)►│                  │
  │                          │                    │─ lazyRefill() ──►│
  │                          │                    │◄─ tokens updated─│
  │                          │                    │─ tryConsume(1) ─►│
  │                          │                    │◄─ allowed=true ──│
  │                          │◄─ (true, 0) ───────│                  │
  │◄── 200 OK ──────────────│                    │                  │
  │  {"allowed":true,        │                    │                  │
  │   "remaining_tokens":47} │                    │                  │
```

### 3.4 Request Flow — Rejected (429)

```
Client              ClientServer          BucketStore           Bucket
  │─ POST /api/v1/request ─►│                    │                  │
  │  X-API-Key: abc123       │─ Allow("abc123",1)►│                  │
  │                          │                    │─ lazyRefill() ──►│
  │                          │                    │─ tryConsume(1) ─►│
  │                          │                    │◄─ allowed=false ─│
  │                          │                    │  retryAfter=200ms│
  │                          │◄─(false, 200ms) ──│                  │
  │◄── 429 ─────────────────│                    │                  │
  │  Retry-After: 0.2       │                    │                  │
```

### 3.5 Scheduler Flow

```
RefillScheduler             Min-Heap               BucketStore
  │─ peek() ───────────────►│                        │
  │◄─ (T1, "abc") ──────────│                        │
  │─ sleep until T1          │                        │
  │                          │                        │
  │─ popAllDue(now) ────────►│                        │
  │◄─ [("abc",T1),("def",T1)]│                       │
  │                          │                        │
  │─ Refill("abc") ─────────────────────────────────►│
  │─ Refill("def") ─────────────────────────────────►│
  │                          │                        │
  │─ push("abc", T1+interval)►│                      │
  │─ push("def", T1+interval)►│                      │
  │─ peek() → sleep next     │                        │
```

### 3.6 Admin Hot-Reconfiguration Flow

```
Admin CLI          AdminServer        BucketStore     Scheduler
  │─ PUT /config ──►│                    │                │
  │                 │─ validate input    │                │
  │                 │─ auditLog(diff) ──►│                │
  │                 │─ updateConfig() ──►│                │
  │                 │                    │─ reschedule()─►│
  │                 │                    │               │─ fix heap
  │                 │◄── ok ─────────────│                │
  │◄── 200 OK ─────│                    │                │
```

Changes apply instantly on next request — no restart or full reload.

### 3.7 Client API (port 8080, TLS)

| Method | Path | Headers | Success | Failure |
|--------|------|---------|---------|---------|
| `POST` | `/api/v1/request` | `X-API-Key: <key>` | 200 `{"allowed":true,"remaining_tokens":N,"reset_at":"..."}` | 429 `{"allowed":false,"remaining_tokens":0,"retry_after_ms":N,"reset_at":"..."}` |

### 3.8 Admin API (port 9090, mTLS/Bearer)

All endpoints require `Authorization: Bearer <admin-token>`.

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/admin/v1/clients/{key}/config` | Update `max_tokens`, `refill_rate`, `refill_interval_ms`. |
| `PUT` | `/admin/v1/clients/{key}/block` | Block client immediately. |
| `PUT` | `/admin/v1/clients/{key}/unblock` | Unblock client. |
| `GET` | `/admin/v1/clients/{key}/status` | Current tokens, config, blocked status. |
| `GET` | `/admin/v1/clients` | Summary list of all tracked clients. |
| `PUT` | `/admin/v1/global/config` | Set global rate limit (bonus). |

---

## 4. Low-Level Design (LLD)

### 4.1 Project Structure

```
sentinel/
├── cmd/
│   ├── sentinel/             # Main service binary
│   │   └── main.go
│   ├── simulator/            # Traffic simulator CLI
│   │   └── main.go
│   └── bonus_demo/           # Bonus features demo CLI
│       └── main.go
├── internal/
│   ├── bucket/               # Token bucket + sliding window integration
│   │   ├── bucket.go
│   │   └── bucket_test.go
│   ├── store/                # BucketStore (thread-safe map + LRU)
│   │   ├── store.go
│   │   └── store_test.go
│   ├── scheduler/            # Min-heap refill scheduler
│   │   ├── heap.go
│   │   ├── scheduler.go
│   │   └── scheduler_test.go
│   ├── server/               # HTTP servers (client + admin)
│   │   ├── client_server.go
│   │   ├── admin_server.go
│   │   └── middleware.go     # TLS, auth, validation, logging middleware
│   ├── config/               # Configuration loading & validation
│   │   └── config.go
│   ├── audit/                # Structured audit logger
│   │   └── audit.go
│   ├── metrics/              # Prometheus metrics
│   │   └── metrics.go
│   ├── security/             # Input sanitization, key validation
│   │   └── sanitize.go
│   ├── window/               # Sliding window rate limiter (bonus 13a)
│   │   ├── window.go
│   │   └── window_test.go
│   ├── multibucket/          # Multi-bucket per client (bonus 13b)
│   │   ├── multibucket.go
│   │   └── multibucket_test.go
│   └── fairness/             # Fairness scheduling (bonus 13d)
│       ├── fairness.go
│       └── fairness_test.go
├── configs/
│   └── sentinel.yaml         # Default configuration
├── certs/                    # TLS certs (gitignored, dev-generated)
├── scripts/
│   ├── gen_certs.sh          # Generate PKI trust chain for dev
│   ├── validate.sh           # Full E2E validation suite (core + bonus)
│   └── validate_bonus.sh     # Bonus features focused validation
├── Dockerfile
├── go.mod
├── Makefile
├── design.md
└── README.md
```

### 4.2 Core Data Structures

#### 4.2.1 Bucket

```go
// internal/bucket/bucket.go

type Config struct {
    MaxTokens        int64
    RefillRate       int64              // Tokens added per interval
    RefillInterval   time.Duration
    TokensPerRequest int64              // Default: 1
    SlidingWindow    *window.Config     // Optional sliding window constraint
}

type Bucket struct {
    configPtr      atomic.Pointer[Config]              // Lock-free config reads
    tokens         atomic.Int64                        // Current tokens (hot path)
    lastRefillTime atomic.Int64                        // Unix nanos of last refill
    blocked        atomic.Bool                         // Admin block flag
    lastAccessTime atomic.Int64                        // For LRU eviction
    createdAt      time.Time
    windowPtr      atomic.Pointer[window.SlidingWindow] // Optional sliding window
}
```

**Design rationale:**
- `tokens`, `lastRefillTime`, `blocked`, `lastAccessTime` are all `atomic` — the hot path (`Allow`) is **entirely lock-free**.
- `configPtr` uses `atomic.Pointer[Config]` — config reads on the hot path require no mutex. Config writes (admin API) atomically swap the pointer.
- `windowPtr` uses `atomic.Pointer` to avoid data races between `Allow()` reads and `UpdateConfig()` writes.
- No `sync.Mutex` on the Bucket struct — the entire type is lock-free.

#### 4.2.2 Allow — Hot Path (Lock-Free CAS)

```go
func (b *Bucket) Allow(n int64, now time.Time) (allowed bool, retryAfter time.Duration) {
    defer func() { /* panic recovery — fail closed */ }()

    if b.blocked.Load() { return false, 0 }

    cfg := b.configPtr.Load()           // Atomic pointer load — no lock
    if cfg.RefillInterval > 0 {
        b.lazyRefill(now, cfg)
    }
    b.lastAccessTime.Store(now.UnixNano())

    for { // CAS loop
        current := b.tokens.Load()
        if current < n {
            if cfg.RefillRate <= 0 || cfg.RefillInterval <= 0 {
                return false, time.Second   // Guard: zero-division
            }
            deficit := n - current
            intervals := (deficit + cfg.RefillRate - 1) / cfg.RefillRate
            return false, time.Duration(intervals) * cfg.RefillInterval
        }
        if b.tokens.CompareAndSwap(current, current-n) {
            // Token bucket allows — now check sliding window
            if w := b.windowPtr.Load(); w != nil && !w.Allow(now) {
                b.tokens.Add(n) // Window rejected — refund tokens
                return false, cfg.RefillInterval
            }
            return true, 0
        }
    }
}
```

#### 4.2.3 Lazy Refill

```go
func (b *Bucket) lazyRefill(now time.Time, cfg *Config) {
    for {
        lastNano := b.lastRefillTime.Load()
        last := time.Unix(0, lastNano)
        elapsed := now.Sub(last)
        intervals := int64(elapsed / cfg.RefillInterval)
        if intervals <= 0 { return }

        newLastNano := last.Add(time.Duration(intervals) * cfg.RefillInterval).UnixNano()
        if !b.lastRefillTime.CompareAndSwap(lastNano, newLastNano) {
            continue  // Another goroutine refilled — retry
        }

        tokensToAdd := intervals * cfg.RefillRate
        for {
            current := b.tokens.Load()
            updated := min(current+tokensToAdd, cfg.MaxTokens)
            if b.tokens.CompareAndSwap(current, updated) { break }
        }
        return
    }
}
```

**Key improvement:** CAS on `lastRefillTime` prevents concurrent double-refill (token inflation). If two goroutines call `lazyRefill` simultaneously, only one wins the CAS — the other retries and sees no elapsed intervals.

Lazy refill guarantees correctness even if the scheduler is delayed — the scheduler is an optimization, not the source of truth.

#### 4.2.4 Min-Heap

```go
// internal/scheduler/heap.go

type RefillEntry struct {
    NextRefillTime time.Time
    ClientKey      string
    HeapIndex      int // Tracked for O(log n) Fix/Remove
}

type RefillHeap []*RefillEntry

// heap.Interface: Len, Less (by NextRefillTime), Swap (update HeapIndex), Push, Pop
```

| Operation | Complexity |
|-----------|------------|
| Peek | O(1) |
| Push | O(log n) |
| Pop | O(log n) |
| Fix (re-heapify after config change) | O(log n) |
| Lookup by key (via `entryMap`) | O(1) |

#### 4.2.5 RefillScheduler

```go
// internal/scheduler/scheduler.go

type Scheduler struct {
    mu       sync.Mutex
    heap     RefillHeap
    entries  map[string]*RefillEntry // clientKey → heap entry (O(1) lookup)
    wakeup   chan struct{}           // Signal to re-evaluate sleep
    store    BucketStoreInterface
    logger   *slog.Logger
    ctx      context.Context
    cancel   context.CancelFunc
}
```

**Scheduler goroutine pseudocode:**
```
loop:
    lock → peek heap → unlock
    if empty: block on wakeup channel
    sleepDuration = entry.NextRefillTime - now
    select:
        case <-timer(sleepDuration):
            lock → popAllDue(now) → unlock
            for each due entry:
                store.Get(key).ScheduledRefill()
                entry.NextRefillTime += interval
                lock → push(entry) → unlock
        case <-wakeup:
            continue  // Config changed or new client added
        case <-ctx.Done():
            return    // Graceful shutdown
```

Only buckets due for refill are touched — no scanning of all N buckets.

#### 4.2.6 BucketStore

```go
// internal/store/store.go

type BucketStore struct {
    mu           sync.RWMutex
    buckets      map[string]*bucket.Bucket
    maxClients   int
    lruList      *list.List            // For eviction ordering
    lruIndex     map[string]*list.Element
    scheduler    SchedulerInterface    // Interface for testability
    defaults     bucket.Config
    logger       *slog.Logger
    globalBucket atomic.Pointer[bucket.Bucket] // Shared global rate limit
}
```

- `Allow()` acquires **read lock** only (fast path for existing clients).
- New bucket creation acquires **write lock** (first-request or admin provision).
- When `len(buckets) >= maxClients`, evict the LRU idle bucket before inserting.

### 4.3 Concurrency Model

| Resource | Mechanism | Why |
|----------|-----------|-----|
| `Bucket.tokens` | `atomic.Int64` + CAS | Lock-free hot path for max throughput. |
| `Bucket.configPtr` | `atomic.Pointer[Config]` | Lock-free config reads; atomic swap on write. |
| `Bucket.windowPtr` | `atomic.Pointer[SlidingWindow]` | Lock-free window reads; avoids race with UpdateConfig. |
| `Bucket.lastRefillTime` | `atomic.Int64` + CAS | Prevents concurrent double-refill (token inflation). |
| `BucketStore.buckets` | `sync.RWMutex` | Many concurrent reads, rare writes (new client / eviction). |
| `BucketStore.globalBucket` | `atomic.Pointer[Bucket]` | Lock-free global rate limit check on every request. |
| `RefillHeap` | `sync.Mutex` | Single scheduler goroutine dominates; brief locks. |
| `Scheduler.entries` | Removed during processing | Entries removed from map while popped from heap to prevent desync. |
| `SlidingWindow` internals | `sync.Mutex` | Timestamp buffer is small; contention is low. |
| `wakeup` | `chan struct{}` (buffered 1) | Non-blocking signal to re-evaluate. |

All shared state tested with Go's `-race` detector in CI.

### 4.4 Configuration

```yaml
# configs/sentinel.yaml
server:
  client_port: 8080
  admin_port: 9090
  tls:
    cert_file: "certs/server.crt"
    key_file: "certs/server.key"
  admin_tls:
    cert_file: "certs/admin.crt"
    key_file: "certs/admin.key"
    client_ca_file: "certs/admin-ca.crt"  # mTLS

defaults:
  max_tokens: 100
  refill_rate: 10
  refill_interval: "1s"
  tokens_per_request: 1
  sliding_window:              # Bonus 13a
    enabled: false
    window_duration: "60s"
    max_requests: 100
    buffer_size: 200

limits:
  max_clients: 100000
  max_api_key_length: 128
  min_refill_interval: "10ms"
  max_refill_interval: "1h"

security:
  admin_token_hash: ""           # bcrypt hash of admin bearer token
  identity_mode: "api_key"       # api_key | ip | api_key_with_ip_fallback
  enable_ip_secondary_limit: true
  ip_max_tokens: 500
  ip_refill_rate: 50
  ip_refill_interval: "1s"

logging:
  level: "INFO"
  audit_file: "logs/audit.json"
  request_sample_rate: 0.01      # Log 1% of allow decisions

metrics:
  enabled: true
  port: 9100
```

### 4.5 Input Validation Rules

| Field | Rule |
|-------|------|
| `X-API-Key` | `^[a-zA-Z0-9_-]{1,128}$` — reject otherwise. |
| `max_tokens` | `1 ≤ v ≤ 1,000,000` |
| `refill_rate` | `1 ≤ v ≤ 100,000` |
| `refill_interval` | `10ms ≤ v ≤ 1h` |
| Admin bearer token | Constant-time bcrypt comparison. |
| Request body (admin) | Max 1 KB. |
| Request body (client) | None expected; reject if present and > 0 bytes. |

All validation failures → `400 Bad Request` with generic message (no internals leaked).

### 4.6 Security Controls

**TLS:**
```go
tls.Config{
    MinVersion:       tls.VersionTLS13,
    CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
}
```

**HTTP Server Hardening:**
- `MaxHeaderBytes`: 4 KB
- `ReadTimeout`: 5 s
- `WriteTimeout`: 5 s
- `IdleTimeout`: 60 s
- Connection limit via `netutil.LimitListener`

**Fail-Closed:**
```go
defer func() {
    if r := recover(); r != nil {
        logger.Error("panic in Allow, failing closed", "panic", r)
        allowed = false // Named return → reject on panic
    }
}()
```

**Anti-Evasion (per-IP secondary limit):**
Even if client rotates API keys, a per-source-IP bucket caps total throughput from that IP (higher limit than per-key, e.g., 500 req/s vs 100 req/s).

### 4.7 Logging & Audit

**Request decision (sampled):**
```json
{"time":"...","level":"DEBUG","msg":"request_decision","client_key":"abc123",
 "source_ip":"10.0.0.5","allowed":true,"tokens_remaining":47,"latency_us":12}
```

**Admin change (always logged):**
```json
{"time":"...","level":"INFO","msg":"admin_config_change","admin":"operator",
 "client_key":"abc123","action":"update_config",
 "before":{"max_tokens":100},"after":{"max_tokens":200},"source_ip":"10.0.0.1"}
```

**Sampling strategy:** configurable rate (default 1%). All 429 rejections and all admin actions are always logged regardless of sample rate.

### 4.8 Metrics (Prometheus)

| Metric | Type | Labels |
|--------|------|--------|
| `sentinel_requests_total` | Counter | `decision` (allow/reject/blocked) |
| `sentinel_request_latency_seconds` | Histogram | — |
| `sentinel_active_clients` | Gauge | — |
| `sentinel_scheduler_refills_total` | Counter | — |
| `sentinel_scheduler_heap_size` | Gauge | — |
| `sentinel_evictions_total` | Counter | — |
| `sentinel_admin_changes_total` | Counter | `action` |

### 4.9 Traffic Simulator

```go
// cmd/simulator/main.go
type ClientProfile struct {
    APIKey    string
    RPS       float64
    BurstSize int
    Duration  time.Duration
    Jitter    time.Duration
}
```

**CLI usage:**
```bash
./simulator --server https://localhost:8080 \
  --clients 50 --rps 100 --burst 20 --duration 60s --jitter 10ms
```

**Output:** Per-client allow/reject counts, p50/p99 latency, total summary.

### 4.10 Graceful Shutdown

1. `SIGINT`/`SIGTERM` caught via `signal.NotifyContext`.
2. Stop accepting new connections on both servers.
3. Cancel scheduler context → scheduler exits loop.
4. `http.Server.Shutdown(ctx)` with 5 s deadline drains in-flight requests.
5. Flush audit logger.
6. Exit.

---

## 5. Bonus Features (Implemented)

| Feature | Status | Implementation |
|---------|--------|----------------|
| **13a: Sliding Window** | ✅ Done | `internal/window/` — Circular buffer of nanosecond timestamps. Counts entries in `[now-window, now]`. Auto-corrects `bufferSize` to `maxRequests+1` minimum. Integrated into `Bucket.Allow()` via `atomic.Pointer`. |
| **13b: Multi-Bucket** | ✅ Done | `internal/multibucket/` — `ClientBuckets` manages independent `map[string]*Bucket` per operation type (read/write/expensive/default). Thread-safe via `sync.RWMutex`. |
| **13c: Global Rate Limit** | ✅ Done | `BucketStore.globalBucket` — `atomic.Pointer[Bucket]` checked before per-client bucket in `Allow()`. Configurable via admin API `PUT /admin/v1/global/config`. |
| **13d: Fairness Scheduling** | ✅ Done | `internal/fairness/` — Weighted fair queuing. Tracks per-client consumption, calculates virtual finish times (`virtualTime + consumed/weight`). Higher consumption = lower priority. |
| **13e: Anti-Evasion** | ✅ Done | Per-IP secondary limiter via `enable_ip_secondary_limit` config. Higher limit than per-key (e.g., 500 vs 100 req/s). |
| **13f: Containerization** | ✅ Done | Multi-stage Dockerfile: Go build → `gcr.io/distroless/static-debian12`. Non-root, read-only FS. Makefile automation. |

### 5.1 Sliding Window Design

```go
// internal/window/window.go
type SlidingWindow struct {
    enabled     bool
    windowSize  time.Duration
    maxRequests int64
    timestamps  []int64        // Circular buffer of nanosecond timestamps
    head        int            // Write position
    count       int            // Current entries in buffer
    mu          sync.Mutex
}
```

- `Allow(now)` counts timestamps within `[now-windowSize, now]`; rejects if `count >= maxRequests`.
- Buffer auto-corrects: if `bufferSize < maxRequests`, it is set to `maxRequests+1` to prevent silent underenforcement.
- `Cleanup(now)` compacts the buffer by removing expired timestamps.
- Integrated into `Bucket.Allow()`: if token bucket allows but window rejects, tokens are refunded.

### 5.2 Multi-Bucket Design

```go
// internal/multibucket/multibucket.go
type ClientBuckets struct {
    clientKey string
    buckets   map[string]*bucket.Bucket  // e.g., "read", "write", "default"
    mu        sync.RWMutex
}
```

- Each bucket type has independent `MaxTokens`, `RefillRate`, and `RefillInterval`.
- Falls back to `"default"` bucket if requested type doesn't exist.
- Fail-closed: if no buckets are configured, requests are denied.

### 5.3 Fairness Scheduling Design

```go
// internal/fairness/fairness.go
type Tracker struct {
    enabled       bool
    consumption   map[string]int64    // clientKey -> total tokens consumed
    weights       map[string]float64  // clientKey -> priority weight
    defaultWeight float64
    virtualTime   float64             // Global virtual time
    mu            sync.RWMutex
}
```

- Virtual finish time: `virtualTime + (consumed / weight)`.
- Higher consumption or lower weight = later finish time = lower priority.
- Weights configurable per client (default: 1.0).

---

## 6. Testing Strategy

| Layer | Tool | Tests | Focus |
|-------|------|-------|-------|
| Unit | `go test` | 48 | Bucket logic, heap operations, store CRUD, window, multibucket, fairness. |
| Concurrency | `go test -race` | All 48 | Race conditions in CAS loops, store access, scheduler, window pointer. |
| E2E | `scripts/validate.sh` | 47 | Full request flow, admin ops, TLS/mTLS, metrics, security, bonus features. |
| Bonus | `scripts/validate_bonus.sh` | 11 | Sliding window, multi-bucket, fairness, runtime config, production scenarios. |
| Load | `cmd/simulator` | — | Configurable: N clients, RPS, burst, duration, jitter. p50/p99 latency. |
| Security | Manual + SAST | — | Input validation bypass, TLS downgrade, admin auth bypass, key rotation. |

---

## 7. Decision Log

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Atomic CAS for token decrement instead of mutex | Lock-free hot path → higher throughput under contention. |
| D2 | Lazy refill + scheduled refill (hybrid) | Lazy = correctness guarantee. Scheduled = proactive, avoids stale buckets. |
| D3 | Separate ports for client and admin | Defense-in-depth: admin port can be firewalled independently. |
| D4 | `slog` (stdlib) over third-party logger | Zero dependencies for logging; structured JSON natively. |
| D5 | HTTP REST over gRPC for v1 | Simpler to test and debug; gRPC can be added later. |
| D6 | LRU eviction at capacity | Prevents unbounded memory; idle clients are lowest-value. |
| D7 | Fail-closed on panic | Security: never allow requests through a broken code path. |
| D8 | bcrypt for admin token storage | Constant-time comparison; resistant to brute force. |
| D9 | `atomic.Pointer[Config]` over `sync.Mutex` for bucket config | Eliminates mutex on hot path entirely; config reads are lock-free. |
| D10 | `atomic.Pointer[SlidingWindow]` for window field | Prevents data race between `Allow()` reads and `UpdateConfig()` writes without adding a mutex. |
| D11 | CAS on `lastRefillTime` in lazy refill | Prevents double-refill (token inflation) when concurrent goroutines call `lazyRefill`. |
| D12 | Auto-correct `bufferSize` to `maxRequests+1` | Prevents silent underenforcement when window buffer is too small. |
| D13 | Remove scheduler entries from map during processing | Prevents `Schedule()` from finding stale entries not in heap, which caused missed refills. |
| D14 | Connection limit: don't double-decrement on reject | `conn.Close()` triggers `StateClosed` callback; manual decrement before close caused negative counter drift. |
