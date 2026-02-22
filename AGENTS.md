# Agent Rules

## Performance

- **NEVER disable or skip optimizations for large programs.** All programs, regardless of size, must receive the same optimization passes. If a pass is too slow, fix the algorithmic complexity (e.g., build indexes, use better data structures) instead of skipping the pass.
- When fixing performance issues, prefer building precomputed indexes (e.g., `HashMap` lookups) over scanning all data structures repeatedly. Convert O(n^2) algorithms to O(n log n) or O(n) using proper indexing.
- Add progress reporting (stderr) for long-running operations so users can see that something is happening. Use `\r` overwriting for TTY output.
