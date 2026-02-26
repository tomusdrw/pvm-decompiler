# Testing Patterns

**Analysis Date:** 2026-02-26

## Test Framework

**Runner:**
- Rust built-in test runner (no external test framework)
- Uses `#[test]` attribute for test functions
- No external dependency on `pytest`, `mocha`, or similar

**Assertion Library:**
- Rust built-in `assert!()`, `assert_eq!()`, `assert_ne!()` macros
- Custom assertion messages with format strings: `assert!(condition, "message: {}", variable)`

**Run Commands:**
```bash
cargo test                    # Run all tests
cargo test -- --nocapture    # Run tests with output visible
cargo test test_fibonacci    # Run specific test by name pattern
```

## Test File Organization

**Location:**
- Co-located in same files as implementation (not separate directory)
- Tests live in `#[cfg(test)] mod tests { ... }` blocks at the end of each file

**Naming:**
- Test functions prefixed with `test_`: `test_fibonacci_full_pipeline()`, `test_decode_known_values()`
- Test modules named `tests`: `mod tests { ... }`
- Regression tests include what they verify: `test_fibonacci_regression_elides_redundant_entry_goto_and_dead_stub_function()`

**Structure:**
- 12 test modules found (one per source file):
  - `src/varint.rs:68-92` — Variable-length integer decoding
  - `src/instruction.rs:1440+` — Instruction classification
  - `src/decoder.rs:855+` — Binary format decoding
  - `src/cfg.rs:275+` — Control flow graph construction
  - `src/functions.rs:781+` — Function boundary detection
  - `src/dataflow.rs:413+` — Data flow analysis
  - `src/lifting.rs:2484+` — Register lifting and variable recovery
  - `src/ir/ssa.rs:359+` — SSA program construction
  - `src/structuring/mod.rs:173+` — Structural analysis API
  - `src/structuring/analysis.rs:648+` — Structure detection (loops, if-then-else)
  - `src/structuring/emission.rs:3029+` — Pseudo-code emission
  - `src/main.rs:833+` — Integration tests

## Test Structure

**Suite Organization:**

Tests are organized as flat functions in `mod tests { ... }` blocks. Examples:

From `src/varint.rs:68-92`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_known_values() {
        assert_eq!(decode_var_u32(&[0]), Some((0, 1)));
        assert_eq!(decode_var_u32(&[1]), Some((1, 1)));
        assert_eq!(decode_var_u32(&[127]), Some((127, 1)));

        assert_eq!(decode_var_u32(&[0x80, 0x80]), Some((128, 2)));
        assert_eq!(decode_var_u32(&[0x80, 0x91]), Some((145, 2)));
        // ... more assertions
    }
}
```

From `src/main.rs:833+`:
```rust
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_fibonacci_full_pipeline() {
        let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
            .expect("fibonacci.pvm fixture should exist");
        let output = decompile_bytes(&buffer)
            .expect("decompilation should succeed");

        assert!(
            output.contains("fn "),
            "Output should contain function definitions: {}",
            output
        );
    }
}
```

**Patterns:**

- **Setup pattern:** File I/O in test, then pass data to function:
  ```rust
  let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
      .expect("fibonacci.pvm fixture should exist");
  let output = decompile_bytes(&buffer)
      .expect("decompilation should succeed");
  ```

- **Teardown pattern:** Not used; tests are stateless with no cleanup needed

- **Assertion pattern:** Single-value assertions or collection assertions with formatted messages:
  ```rust
  assert_eq!(decode_var_u32(&[0]), Some((0, 1)));

  assert!(
      output.contains("while") || output.contains("for") || output.contains("if"),
      "Fibonacci should contain loops or branches: {}",
      output
  );

  assert!(!output.contains("goto block_000a;"),
      "Linear entry jumps should be elided: {}", output);
  ```

## Mocking

**Framework:**
- No external mocking library (no `mockito`, `mock`, or similar)
- Mocking implemented manually through builder patterns and test fixtures

**Patterns:**
- Fixture files: Real PVM bytecode stored in `examples/compiled/` directory (fibonacci.pvm, br-table.pvm, simple-add.pvm, life-simple.pvm, ananas.pvm)
- Fixture-based testing: Tests load real binaries and verify decompilation output
- No mock objects or trait mocks observed

**What to Mock:**
- File I/O: Tests load real fixture files from disk rather than mocking filesystem
- External libraries: `wasm_pvm` crate is a real dependency, not mocked

**What NOT to Mock:**
- Core decompilation pipeline: Tests run actual decoder, CFG builder, analysis passes (integration testing approach)
- Register lifting: Tests verify lifted output against fixtures
- Structural analysis: Tests verify loop/if-then-else detection against real programs

## Fixtures and Factories

**Test Data:**
No factory pattern observed. Fixtures are real compiled PVM binaries:
- `examples/compiled/fibonacci.pvm` — Fibonacci implementation (200+ lines of disassembly)
- `examples/compiled/br-table.pvm` — Branch table testing
- `examples/compiled/simple-add.pvm` — Addition operation
- `examples/compiled/life-simple.pvm` — Conway's Game of Life variant
- `examples/compiled/ananas.pvm` — Complex program

Example fixture usage:
```rust
let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
    .expect("fibonacci.pvm fixture should exist");
let output = decompile_bytes(&buffer)
    .expect("decompilation should succeed");
```

**Location:**
- Binary fixtures: `examples/compiled/*.pvm`
- Tests access via relative paths (`"examples/compiled/..."`), implying test is run from project root

## Coverage

**Requirements:**
- No coverage requirements enforced (no `.coverage` config, no CI coverage gates)
- Coverage analysis: Not performed or reported

**View Coverage:**
- Not configured in Cargo.toml or CI
- Manual coverage with `cargo tarpaulin` or `llvm-cov` would be external

## Test Types

**Unit Tests:**
- Scope: Single functions or small modules
- Approach: Direct function calls with input/output verification
- Examples:
  - `test_decode_known_values()` tests `decode_var_u32()` with fixed inputs
  - `src/instruction.rs` tests instruction classification against raw Instruction variants
  - `src/dataflow.rs` tests def-use chain computation on small CFGs

**Integration Tests:**
- Scope: Multiple analysis passes (decoder → CFG → dataflow → lifting → structuring)
- Approach: Load PVM bytecode fixtures and verify end-to-end decompilation output
- Examples:
  - `test_fibonacci_full_pipeline()` verifies functions, loops, and returns exist in output
  - `test_fibonacci_regression_elides_redundant_entry_goto_and_dead_stub_function()` verifies optimization (no redundant gotos)
  - `test_fibonacci_regression_inverts_loop_condition_and_elides_forwarder_jump()` verifies condition inversion

**E2E Tests:**
- Not used (no separate E2E test framework)
- Integration tests in `src/main.rs` module serve as E2E verification

## Common Patterns

**Async Testing:**
- Not applicable (Rust async/await not used in this codebase)

**Error Testing:**
- Positive assertions (success paths tested primarily)
- Error cases tested via return type checks:
  ```rust
  assert_eq!(decode_var_u32(&[]), None);  // Insufficient data
  ```
- No error injection patterns observed

**Fixture Setup:**
```rust
#[test]
fn test_name() {
    // Read fixture
    let buffer = std::fs::read("examples/compiled/name.pvm")
        .expect("fixture should exist");

    // Call function under test
    let output = decompile_bytes(&buffer)
        .expect("decompilation should succeed");

    // Assertions on output
    assert!(output.contains("expected_content"));
}
```

**Regression Testing:**
- Test names explicitly document what regression they prevent:
  - `test_fibonacci_regression_elides_redundant_entry_goto_and_dead_stub_function()`
  - `test_fibonacci_regression_inverts_loop_condition_and_elides_forwarder_jump()`
  - `test_fibonacci_regression_elides_dead_pre_halt_setup_noise()`

**Property Verification in Assertions:**
Tests verify properties rather than exact output:
```rust
assert!(output.contains("fn "), "should have functions");
assert!(output.contains("while") || output.contains("for"),
    "should have loops");
assert!(!output.contains("goto block_000a;"),
    "should not have redundant jumps");
```

**String Search Assertions:**
- Many tests use `.contains()` to verify pseudo-code output
- Tests check for absence of optimization artifacts: `!output.contains("redundant_pattern")`
- Tests verify structural elements exist: `output.contains("fn ")`, `output.contains("while")`

## Test Coverage Summary

**Coverage by module:**
- `varint.rs`: 1 test (decode variations)
- `instruction.rs`: Multiple tests (classification, formatting)
- `decoder.rs`: Multiple tests (SPI format, raw format)
- `cfg.rs`: Multiple tests (block splitting, edge connections)
- `functions.rs`: Multiple tests (function boundary detection)
- `dataflow.rs`: Multiple tests (def-use chains, liveness)
- `lifting.rs`: Multiple tests (variable recovery, expression simplification)
- `ir/ssa.rs`: Multiple tests (SSA construction)
- `structuring/mod.rs`: Multiple tests (condition extraction)
- `structuring/analysis.rs`: Multiple tests (loop/if detection)
- `structuring/emission.rs`: Multiple tests (pseudo-code output, optimizations)
- `main.rs`: 9+ integration tests (full pipeline on fixtures)

**Test execution:**
All tests are inline in source and executed via `cargo test`.

---

*Testing analysis: 2026-02-26*
