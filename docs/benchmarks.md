# QUIC Performance Benchmarks & Research

**Goal:** Build the fastest, most reliable QUIC transport library in Rust.

**Method:** Systematic benchmarking against all major Rust QUIC implementations,
finding performance gaps, understanding root causes, and adopting best patterns.

---

## Implementations Under Test

| # | Library | Version | Org | TLS Backend | Async Model |
|---|---------|---------|-----|-------------|-------------|
| 1 | **tquic (our fork)** | develop | tolkichat | BoringSSL | Arc<Mutex> + EndpointDriver Future |
| 2 | **Quinn** | 0.11.x | quinn-rs | rustls | Arc<Mutex> + EndpointDriver Future |
| 3 | **tquic (original)** | 0.21.x | Tencent | BoringSSL | Rc<RefCell> + mio event loop |
| 4 | **quiche** | 0.22.x | Cloudflare | BoringSSL | C core + Rust FFI, poll-based |
| 5 | **s2n-quic** | 1.x | AWS | s2n-tls/rustls | tokio native, io-uring optional |
| 6 | **neqo** | 0.10.x | Mozilla | NSS | sync poll-based, no async runtime |

---

## Benchmark Categories

### 1. Handshake Latency
- Time from `connect()` to `established()`
- 1-RTT and 0-RTT variants
- Metrics: mean, P50, P95, P99
- Isolate TLS from QUIC overhead

### 2. Stream Throughput
- Unidirectional + bidirectional
- Payload sizes: 1 KB, 64 KB, 1 MB, 10 MB
- Single stream and concurrent (1, 10, 100 streams)
- Metrics: MB/s, CPU utilization per MB

### 3. Datagram Throughput
- Unreliable DATAGRAM frames (RFC 9221)
- Packet sizes: 64 B, 512 B, 1200 B (MTU)
- Metrics: packets/sec, bytes/sec, loss rate

### 4. Connection Scalability
- Concurrent connections: 10, 100, 500, 1000
- Memory per connection
- Degradation curve (throughput vs connection count)

### 5. Lock Contention & CPU
- Mutex acquisition cost under load
- CPU profile (perf/flamegraph)
- Context switches per operation

### 6. Latency Under Load
- Stream write-to-read latency with background traffic
- Tail latency (P99, P99.9)
- Jitter measurement

### 7. Resilience
- Behavior under packet loss (0%, 1%, 5%, 10%)
- Recovery time after network interruption
- Connection migration (if supported)

---

## Results

### Round 1: Baseline (TBD)

> First benchmark run on localhost, no artificial loss/delay.
> All implementations use self-signed certs, QUIC v1, default configs.

#### Handshake Latency (localhost, 1-RTT)

| Library | Mean | P50 | P95 | P99 | Notes |
|---------|------|-----|-----|-----|-------|
| tquic (ours) | - | - | - | - | |
| Quinn | - | - | - | - | |
| tquic (orig) | - | - | - | - | |
| quiche | - | - | - | - | |
| s2n-quic | - | - | - | - | |
| neqo | - | - | - | - | |

#### Stream Throughput (single stream, 1 MB payload)

| Library | MB/s | CPU% | Notes |
|---------|------|------|-------|
| tquic (ours) | - | - | |
| Quinn | - | - | |
| tquic (orig) | - | - | |
| quiche | - | - | |
| s2n-quic | - | - | |
| neqo | - | - | |

#### Datagram Rate (1200 B packets)

| Library | pkt/s | MB/s | Loss% | Notes |
|---------|-------|------|-------|-------|
| tquic (ours) | - | - | - | |
| Quinn | - | - | - | |
| tquic (orig) | - | - | - | |
| quiche | - | - | - | |
| s2n-quic | - | - | - | |
| neqo | - | - | - | |

---

## Observations & Analysis

### Architecture Comparison

#### Quinn
- **Strengths:** (TBD after benchmarks)
- **Weaknesses:** (TBD)
- **Key patterns to study:**
  - Batched UDP send/recv (GRO/GSO)
  - Lock-free connection map
  - Timer management (single Sleep future)

#### s2n-quic
- **Strengths:** (TBD)
- **Weaknesses:** (TBD)
- **Key patterns to study:**
  - io-uring integration
  - Platform-specific optimizations
  - Monte Carlo testing methodology

#### quiche (Cloudflare)
- **Strengths:** (TBD)
- **Weaknesses:** (TBD)
- **Key patterns to study:**
  - C core performance
  - FFI overhead measurement

#### neqo (Mozilla)
- **Strengths:** (TBD)
- **Weaknesses:** (TBD)
- **Key patterns to study:**
  - NSS crypto performance
  - Firefox-grade reliability

#### tquic (Tencent original)
- **Strengths:** (TBD)
- **Weaknesses:** (TBD)
- **Key patterns to study:**
  - Multipath QUIC
  - BBRv3 congestion control

---

## Performance Gaps & Action Items

> After each benchmark round, document gaps and planned fixes here.

### Gap Template

```
## Gap: [short description]
- **Observed:** our tquic = X, Quinn = Y (delta: Z%)
- **Root cause:** [analysis from profiling/code review]
- **Fix plan:** [what to change]
- **Status:** [ ] Identified  [ ] Analyzed  [ ] Fixed  [ ] Verified
```

---

## Bugs Found Through Benchmarks

> Benchmarks often reveal correctness issues under load.

| # | Bug | Found via | Severity | Status |
|---|-----|-----------|----------|--------|
| | | | | |

---

## Environment

- **Hardware:** (TBD — document CPU, RAM, NIC)
- **OS:** Linux 6.14, Ubuntu
- **Rust:** (TBD — `rustc --version`)
- **Build:** `--release` with LTO
- **Network:** localhost (round 1), tc/netem for loss simulation (round 2+)

## Methodology

1. All benchmarks run in `--release` mode with `opt-level = 3`
2. Same TLS configuration where possible (self-signed certs)
3. CPU pinning via `core_affinity` to reduce noise
4. Minimum 30 samples per measurement (criterion default)
5. Warm-up phase before measurement
6. Results include confidence intervals
7. Flamegraphs for any result >20% slower than best

## Benchmark Crate

Location: `/src/tolki/tquic/benches/`
Framework: criterion.rs (primary) + divan (parameterized)

```bash
# Run all benchmarks
cargo bench -p tquic --features tokio-runtime

# Run specific category
cargo bench -p tquic --features tokio-runtime -- handshake
cargo bench -p tquic --features tokio-runtime -- throughput
cargo bench -p tquic --features tokio-runtime -- datagram

# Generate HTML report
# Results at: target/criterion/report/index.html
```

---

## Changelog

| Date | Round | Changes |
|------|-------|---------|
| 2026-02-11 | - | Document created, 6 implementations selected |
| | Round 1 | TBD: Baseline localhost benchmarks |
| | Round 2 | TBD: With network simulation (loss, RTT) |
| | Round 3 | TBD: After optimization pass |
