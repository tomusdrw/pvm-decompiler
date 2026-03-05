LLVM Decompiler Plan

- Target pipeline: lift PVM bytecode to LLVM bitcode, run an off‑the‑shelf LLVM‑based decompiler (e.g., Rellic) to generate structured C, then pipe that C through an LLM refinement stage (DeGPT/D‑LiFT style) so the final pseudo‑code regains readability, comments, and semantic hints while preserving accuracy. (github.com)
- Phase 1 – Hook points: inspect src/{decoder,cfg,lifting,structuring} to see what assumptions the current pipeline makes about control flow, dataflow, and type recovery so we can replace only the “lift-to-pseudo” stage, keep the binary parsing logic, and expose the instruction stream that a new lifter will consume.
- Phase 2 – LLVM lift: design (or adapt) a translator that consumes PVM instructions/CFGs and emits LLVM IR/bitcode, reusing remill semantics for similar instructions where possible. If necessary, add a custom front end or adapter similar to McSema’s separation of control-flow recovery (mcsema-disass) and instruction translation (mcsema-lift), but target the PVM ISA instead of x86/ARM. (github.com)
- Phase 3 – Decompiler integration: pick a ready-made LLVM decompiler such as Rellic (goto-free C output from LLVM bitcode) or RetDec, run it on the lifted bitcode, and feed its structured C back into our tooling chain; keep canonical LLVM bitcode as the “immediate representation” shared between translation and decompilation to simplify testing and debugging. (github.com)
- Phase 4 – LLM refinement: wrap the C from Rellic/RetDec with a DeGPT or D-LiFT style loop—issue rounds of “referee/advisor/operator” prompts that improve naming, comments, and control-flow clarity while verifying semantics (syntactic checks, compilers/symbolic execution, scoring models). Use the refinement loop to merge outputs back into our UI/CLI so reverse engineers see both raw decompiler output and the LLM-polished version. (ndss-symposium.org)
- Phase 5 – Evaluation & rollout: define measurable goals (e.g., readability scores, naming coverage, semantic equivalence via symbolic checks or unit tests) and build benchmarks (existing examples/output/ runs) to compare current pseudo-code vs. new pipeline. Document the fallback path (continue using current renderer when the LLVM lift or LLM fail) so regressions are avoidable.

Next steps:

1. Prototype the translator to LLVM IR and verify it produces sound bitcode for a handful of PVM binaries.
2. Wire in Rellic/RetDec decompilation and exercise it inside the CLI.
3. Build the LLM refinement harness (DeGPT role pipeline + accuracy guard) and hook it up to the new flow.
