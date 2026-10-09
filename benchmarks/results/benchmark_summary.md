# Benchmark Results

## Environment

- **python**: 3.14.7
- **implementation**: CPython
- **platform**: Windows-11-10.0.26300-SP0
- **processor**: Intel64 Family 6 Model 154 Stepping 4, GenuineIntel

## Throughput summary

```text
Ed25519 sign (512 B)                   ############################## 18,131 ops/s
Ed25519 verify (512 B)                 ########### 6,672 ops/s
authorize (in-memory log)              ############# 8,092 ops/s
authorize + execute (in-memory log)    #### 2,250 ops/s
authorize + execute (SQLite log)       # 34 ops/s
replayed artifact rejected             #### 2,260 ops/s
verify 2,000-frame hash chain          ######################### 15,292 frames/sec
authorize + execute over HTTP, 1 client(s) # 106 ops/s
authorize + execute over HTTP, 4 client(s) # 165 ops/s
authorize + execute over HTTP, 16 client(s) # 29 ops/s
```

### In-process barrier

| Benchmark | Iterations | Throughput | Mean | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 sign (512 B) | 400 | 18,131 ops/s | 55 µs | 52 µs | 66 µs | 116 µs |
| Ed25519 verify (512 B) | 400 | 6,672 ops/s | 150 µs | 138 µs | 207 µs | 362 µs |
| authorize (in-memory log) | 100 | 8,092 ops/s | 123 µs | 115 µs | 165 µs | 264 µs |
| authorize + execute (in-memory log) | 100 | 2,250 ops/s | 444 µs | 345 µs | 525 µs | 2,635 µs |
| authorize + execute (SQLite log) | 200 | 34 ops/s | 29,670 µs | 30,856 µs | 39,164 µs | 41,697 µs |
| replayed artifact rejected | 100 | 2,260 ops/s | 441 µs | 330 µs | 1,040 µs | 2,259 µs |
| verify 2,000-frame hash chain | 1 | 15,292 frames/sec | 130,790 µs | - | - | - |

### HTTP API (one authorize + one execute per iteration)

| Benchmark | Iterations | Throughput | Mean | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|---:|
| authorize + execute over HTTP, 1 client(s) | 40 | 106 ops/s | 9,411 µs | 9,181 µs | 11,165 µs | 11,776 µs |
| authorize + execute over HTTP, 4 client(s) | 40 | 165 ops/s | 23,514 µs | 23,894 µs | 27,339 µs | 32,187 µs |
| authorize + execute over HTTP, 16 client(s) | 32 | 29 ops/s | 231,410 µs | 53,689 µs | 1,041,594 µs | 1,056,223 µs |

## Interpretation

- The signed GAA barrier stays inexpensive in memory; the dominant operational cost is durable replay storage and HTTP serialization.
- The SQLite path is slower because every append and nonce claim is a transactional write. This is a good production signal for keeping the authorization log on a managed database or append-only store.
- The HTTP path scales to a few concurrent clients while showing tail latency growth; production deployments should run behind a load balancer and keep the benchmark environment close to the target deployment profile.