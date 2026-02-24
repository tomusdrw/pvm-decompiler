# Agent Rules

## Performance

- **NEVER disable or skip optimizations for large programs.** All programs, regardless of size, must receive the same optimization passes. If a pass is too slow, fix the algorithmic complexity (e.g., build indexes, use better data structures) instead of skipping the pass.
- When fixing performance issues, prefer building precomputed indexes (e.g., `HashMap` lookups) over scanning all data structures repeatedly. Convert O(n^2) algorithms to O(n log n) or O(n) using proper indexing.
- Add progress reporting (stderr) for long-running operations so users can see that something is happening. Use `\r` overwriting for TTY output.

## Commits

- **Always regenerate examples before each commit.** Run `./run_examples.sh` to update all example outputs so they reflect the latest changes.

## Testing

- **Bug fixes must include a regression test.** When the user reports something broken and asks for a fix, implement the fix and add/adjust a unit or integration test in the same change so the issue is covered and prevented from regressing. If a test is not feasible, explicitly explain why.
