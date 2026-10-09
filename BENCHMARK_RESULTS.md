# Benchmark Results

The GAS governance barrier was benchmarked using the real authorization path: Ed25519 signing, policy evaluation, replay log append, execution boundary verification, and HTTP transport. The full machine-readable and CSV exports are stored in `benchmarks/results/`.

## Files

- `benchmarks/results/benchmark_results.json`
- `benchmarks/results/benchmark_results.csv`
- `benchmarks/results/benchmark_summary.md`

## Environment

- Python: 3.14.7
- Implementation: CPython
- Platform: Windows-11-10.0.26300-SP0
- Processor: Intel64 Family 6 Model 154 Stepping 4, GenuineIntel

## Executive summary

- In-memory authorization and execution remain inexpensive: authorization + execute is roughly 0.44 ms in the local barrier path.
- Durable SQLite replay storage is the main cost driver, validating the need for a managed transactional log in production.
- HTTP throughput remains healthy for a few concurrent clients; concurrency beyond that should be managed with load balancing and a durable backing store.

## Throughput chart

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

## Key conclusions

1. The cryptographic barrier is not the bottleneck for agent workloads under ordinary conditions.
2. Replay integrity verification and policy re-evaluation are strongly bounded and deterministic.
3. Operational risk shifts to durable storage and HTTP scaling, not to the GAA-signing logic itself.

## Recommendation

Use the benchmark to size the production deployment around a durable transaction log and a horizontally scaled HTTP edge. The current results support the platform architecture without claiming broad load-test maturity beyond this local benchmark run.
