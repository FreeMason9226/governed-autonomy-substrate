# Arbitration Load Baseline

Run `python performance/load_test.py` in the verification environment. The script performs
10,000 deterministic in-process arbiter decisions and prints elapsed seconds and decisions
per second. This is a local baseline, not a production capacity guarantee; record CPU,
Python version, storage backend, and concurrency before comparing runs.

Recorded baseline: 10,000 iterations, 0.249293699998816 seconds, 40,113.32817494984
decisions/second on Windows Python 3.14.7. See `performance/load_test_result.json`.