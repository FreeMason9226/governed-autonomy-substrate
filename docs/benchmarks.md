# Performance benchmarks

Reproduce with:

```bash
python benchmarks/bench.py --json benchmarks/results.json
```

The harness (`benchmarks/bench.py`) exercises the real code paths: Ed25519 signing, the issuer, the execution barrier, replay logs and the HTTP server. Raw results from the run below are in [`benchmarks/results.json`](../benchmarks/results.json).

## Reference run

Environment: CPython 3.14.7, Windows 11, Intel Core (family 6 model 154, laptop-class), single process, no tuning.

### In-process barrier

| Benchmark | Iterations | Throughput | Mean | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 sign (512 B) | 8,000 | 24,970 ops/s | 40 µs | 39 µs | 44 µs | 71 µs |
| Ed25519 verify (512 B) | 8,000 | 8,829 ops/s | 113 µs | 108 µs | 147 µs | 200 µs |
| authorize (in-memory log) | 2,000 | 9,512 ops/s | 105 µs | 92 µs | 179 µs | 260 µs |
| authorize + execute (in-memory log) | 2,000 | 2,724 ops/s | 367 µs | 347 µs | 575 µs | 740 µs |
| authorize + execute (SQLite log) | 500 | 41 ops/s | 24,616 µs | 23,220 µs | 32,214 µs | 41,144 µs |
| replayed artifact rejected | 2,000 | 8,151 ops/s | 122 µs | 116 µs | 175 µs | 211 µs |
| verify 2,000-frame hash chain | 1 | 48,236 frames/s | 41 ms | - | - | - |

### HTTP API (one authorize + one execute per iteration)

| Clients | Iterations | Throughput | Mean | p50 | p95 | p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 800 | 202 ops/s | 4.9 ms | 4.8 ms | 7.3 ms | 8.5 ms |
| 4 | 800 | 364 ops/s | 10.9 ms | 10.6 ms | 14.7 ms | 15.9 ms |
| 16 | 800 | 228 ops/s | 45.8 ms | 22.1 ms | 38.8 ms | 554 ms |

## Reading the numbers

- **The cryptographic barrier is cheap.** A full authorize + verify + execute cycle costs about 0.37 ms in memory; the barrier is not the bottleneck for agent workloads.
- **Durability dominates.** The SQLite log is ~65x slower because every append and nonce claim is an fsync'd transaction. Expect the Postgres log to be bound by round-trip latency and commit time; benchmark it in your own environment.
- **HTTP numbers reflect the stdlib `ThreadingHTTPServer`** plus a new connection per request path and the Python GIL. Throughput peaks at a few clients and tail latency grows at 16. For higher concurrency, run several replicas behind a load balancer (the Helm chart defaults to 2) with the Postgres store.
- Verification of the audit chain is linear: roughly 48k frames/s.

## Caveats

- Single run on a developer machine; numbers vary by CPU, OS and Python version. Run the script on your target hardware before capacity planning.
- Rate limiting is effectively disabled during the HTTP test; production defaults will throttle earlier.
- The Postgres backend and the KMS signer are not covered: they depend on network latency and provider performance.
