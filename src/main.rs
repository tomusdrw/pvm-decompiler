use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use wasm_pvm::pvm::Instruction;

mod cfg;
mod dataflow;
mod decoder;
mod functions;
mod instruction;
mod lifting;
mod structuring;
mod varint;

use cfg::ControlFlowGraph;
use dataflow::DataFlowAnalysis;
use functions::{
    build_call_graph, build_function_cfg, detect_direct_call_patterns, detect_epilogues,
    detect_functions, detect_prologue,
};
use lifting::LiftedProgram;
use structuring::{DominatorTree, FunctionSignature, StructuralAnalysis};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verbosity {
    /// Default: only pseudo-code output
    Normal,
    /// -v/--verbose: include CFG, dataflow, and structural summaries
    Verbose,
    /// --debug: include raw instructions and all diagnostics
    Debug,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Parse flags
    let mut verbosity = Verbosity::Normal;
    let mut filename = None;

    for arg in &args[1..] {
        match arg.as_str() {
            "-v" | "--verbose" => verbosity = Verbosity::Verbose,
            "--debug" => verbosity = Verbosity::Debug,
            "-h" | "--help" => {
                eprintln!("Usage: {} [OPTIONS] <file.pvm>", args[0]);
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -v, --verbose  Show CFG, dataflow, and structural analysis");
                eprintln!("      --debug    Show raw instructions and all diagnostics");
                eprintln!("  -h, --help     Show this help message");
                return Ok(());
            }
            _ => {
                if arg.starts_with('-') {
                    eprintln!("Unknown option: {}", arg);
                    return Ok(());
                }
                filename = Some(arg.clone());
            }
        }
    }

    let filename = match filename {
        Some(f) => f,
        None => {
            eprintln!("Usage: {} [OPTIONS] <file.pvm>", args[0]);
            return Ok(());
        }
    };

    use std::fmt::Write as FmtWrite;
    let mut all_output = String::new();

    if verbosity >= Verbosity::Verbose {
        let _ = writeln!(all_output, "Reading {}...", filename);
    }

    let mut file = fs::File::open(&filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Strip metadata prefix if present, then try SPI format, fall back to raw blob
    let stripped = decoder::try_strip_metadata(&buffer)?;
    let program = match decoder::decode_spi(stripped) {
        Ok(prog) => {
            if verbosity >= Verbosity::Verbose {
                let _ = writeln!(all_output, "Successfully decoded as SPI format");
            }
            prog
        }
        Err(e) => {
            if verbosity >= Verbosity::Verbose {
                eprintln!("SPI decode failed: {}, trying raw blob format...", e);
            }
            decoder::decode_blob(stripped)?
        }
    };

    // Report unknown instructions (always on stderr as warnings)
    let mut unknown_opcodes: HashMap<u8, usize> = HashMap::new();
    for (_, instr) in &program.instructions {
        if let Instruction::Unknown { opcode, .. } = instr {
            *unknown_opcodes.entry(*opcode).or_default() += 1;
        }
    }
    if !unknown_opcodes.is_empty() {
        let mut sorted: Vec<_> = unknown_opcodes.iter().collect();
        sorted.sort_by_key(|(op, _)| **op);
        eprintln!(
            "Warning: {} unknown opcode(s) encountered:",
            sorted.iter().map(|(_, c)| *c).sum::<usize>()
        );
        for (opcode, count) in sorted {
            eprintln!("  opcode {:#04x}: {} occurrence(s)", opcode, count);
        }
        eprintln!();
    }

    // Debug: raw instruction dump
    if verbosity >= Verbosity::Debug {
        let _ = writeln!(all_output, "Jump Table: {:?}", program.jump_table);
        if let Some(base) = program.memory_base {
            let _ = writeln!(all_output, "Memory Base: {:#x} ({})", base, base);
        }
        let _ = writeln!(all_output, "\nInstructions:");
        for (pc, instr) in program.instructions.iter() {
            let _ = writeln!(all_output, "  PC {:#06x}: {:?}", pc, instr);
        }
    }

    // Build global CFG
    let cfg = ControlFlowGraph::build(&program);
    if verbosity >= Verbosity::Debug {
        let _ = writeln!(all_output, "\n=== Control Flow Graph ===");
        write_cfg(&cfg, &mut all_output);
    }

    // Detect function boundaries
    let detected_functions = detect_functions(&cfg);
    if verbosity >= Verbosity::Verbose {
        let _ = writeln!(
            all_output,
            "\n=== Function Detection ===\nDetected {} function(s):",
            detected_functions.len()
        );
        for func in &detected_functions {
            let mut sorted_blocks: Vec<usize> = func.block_pcs.iter().copied().collect();
            sorted_blocks.sort();
            let _ = writeln!(
                all_output,
                "  {} @ {:#06x} ({} blocks: {:?})",
                func.name,
                func.entry_pc,
                func.block_pcs.len(),
                sorted_blocks
            );
        }
    }

    // Build call graph
    let call_graph = build_call_graph(&cfg, &detected_functions, &program);
    if verbosity >= Verbosity::Verbose && !call_graph.is_empty() {
        let _ = writeln!(all_output, "\n=== Call Graph ===");
        for func in &detected_functions {
            if let Some(calls) = call_graph.get(&func.entry_pc) {
                for call in calls {
                    let _ = writeln!(
                        all_output,
                        "  {} (block {:#06x}) → {}",
                        func.name, call.caller_block_pc, call.callee_name
                    );
                }
            }
        }
    }

    // Detect direct call patterns: LoadImm64 r0 + Jump
    let direct_call_patterns = detect_direct_call_patterns(&cfg, &detected_functions, &program);
    if verbosity >= Verbosity::Verbose && !direct_call_patterns.is_empty() {
        let _ = writeln!(all_output, "\n=== Direct Call Patterns ===");
        for pat in &direct_call_patterns {
            let _ = writeln!(
                all_output,
                "  block {:#06x}: call {} (jump to {:#06x}, return to {:#06x})",
                pat.caller_block_pc, pat.callee_name, pat.jump_target_pc, pat.return_pc
            );
        }
    }

    // Build a flat lookup from callee_entry_pc → callee_name for pseudo-code emission.
    // This lets the emitter recognize Jump targets that are function entries.
    let mut call_targets: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    // Build indirect call targets: caller_block_pc → callee_name (for JumpInd-based calls)
    let mut indirect_call_targets: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    // PCs to eliminate from output (e.g., LoadImm64 setting return address in call patterns)
    let mut call_pattern_eliminated_pcs: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    for calls in call_graph.values() {
        for call in calls {
            call_targets.insert(call.callee_entry_pc, call.callee_name.clone());
            // Check if the caller block ends with JumpInd (indirect call via jump table)
            if let Some(block) = cfg.blocks.get(&call.caller_block_pc)
                && let Some((_, last_instr)) = block.instructions.last()
                && matches!(last_instr, Instruction::JumpInd { .. })
            {
                indirect_call_targets.insert(call.caller_block_pc, call.callee_name.clone());
            }
        }
    }
    // Add direct call pattern targets: map the Jump target PC to the callee name
    for pat in &direct_call_patterns {
        call_targets.insert(pat.jump_target_pc, pat.callee_name.clone());
        call_pattern_eliminated_pcs.insert(pat.load_imm_pc);
    }

    // Compute function entry PCs for dispatch switch classification
    let function_entry_pcs: std::collections::HashSet<usize> =
        detected_functions.iter().map(|f| f.entry_pc).collect();

    // Set memory base for expression formatting
    lifting::set_memory_base(program.memory_base);

    // Process each function independently
    let total_funcs = detected_functions.len();
    let is_tty = atty::is(atty::Stream::Stderr);

    for (func_idx, func) in detected_functions.iter().enumerate() {
        // Progress reporting: show function name and step
        let progress = |step: &str| {
            if is_tty {
                eprint!(
                    "\r\x1b[K[{}/{}] {} ({} blocks): {}",
                    func_idx + 1,
                    total_funcs,
                    func.name,
                    func.block_pcs.len(),
                    step
                );
            }
        };

        if verbosity >= Verbosity::Verbose {
            // In verbose mode, use line-based output instead of overwriting
            eprintln!(
                "[{}/{}] Processing {} ({} blocks)...",
                func_idx + 1,
                total_funcs,
                func.name,
                func.block_pcs.len()
            );
        } else {
            progress("building CFG...");
        }

        let func_cfg = build_function_cfg(&cfg, func);

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Computing dominator tree...");
        } else {
            progress("dominator tree...");
        }
        let dom_tree = DominatorTree::compute(&func_cfg);

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Running dataflow analysis...");
        } else {
            progress("dataflow analysis...");
        }
        let dataflow = DataFlowAnalysis::analyze(&func_cfg);

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Lifting expressions...");
        } else {
            progress("lifting expressions...");
        }
        let mut lifted = LiftedProgram::analyze_with_dom_tree(&func_cfg, &dataflow, &dom_tree);
        lifted.call_targets = call_targets.clone();
        lifted.indirect_call_targets = indirect_call_targets.clone();
        lifted.memory_base = program.memory_base;

        // Detect epilogues (return/halt patterns) and prologues (stack guard, frame alloc, reg saves)
        let epilogues = detect_epilogues(&func_cfg);
        let prologue_pcs = detect_prologue(&func_cfg, func.entry_pc);
        for (block_pc, kind) in &epilogues {
            match kind {
                functions::EpilogueKind::Return { eliminated_pcs }
                | functions::EpilogueKind::Halt { eliminated_pcs } => {
                    for &pc in eliminated_pcs {
                        lifted.eliminated_pcs.insert(pc);
                    }
                }
            }
            lifted.epilogue_blocks.insert(*block_pc, kind.clone());
        }
        for &pc in &prologue_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        // Eliminate LoadImm64 instructions from call patterns (return address setup)
        for &pc in &call_pattern_eliminated_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        // Suppress callee blocks that were misassigned to this function.
        let caller_block_pcs: HashSet<usize> = direct_call_patterns
            .iter()
            .flat_map(|p| [p.caller_block_pc, p.return_pc])
            .collect();
        for pat in &direct_call_patterns {
            if func.block_pcs.contains(&pat.jump_target_pc) && pat.callee_name != func.name {
                let mut queue = std::collections::VecDeque::new();
                queue.push_back(pat.jump_target_pc);
                while let Some(bp) = queue.pop_front() {
                    if lifted.suppressed_blocks.insert(bp)
                        && let Some(block) = func_cfg.blocks.get(&bp)
                    {
                        for &succ in &block.successors {
                            if !lifted.suppressed_blocks.contains(&succ)
                                && !caller_block_pcs.contains(&succ)
                            {
                                queue.push_back(succ);
                            }
                        }
                    }
                }
            }
        }

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Running structural analysis...");
        } else {
            progress("structural analysis...");
        }
        let structural = StructuralAnalysis::analyze_with_dom_tree(
            &func_cfg,
            &program,
            dom_tree,
            function_entry_pcs.clone(),
        );

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Emitting pseudo-code...");
        } else {
            progress("emitting pseudo-code...");
        }

        // Compute function signature from live-in registers at entry block
        let mut params: Vec<u8> = dataflow
            .live_in
            .get(&func.entry_pc)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        params.sort();
        let sig = FunctionSignature {
            name: func.name.clone(),
            params,
        };

        if verbosity >= Verbosity::Verbose {
            let _ = writeln!(all_output, "\n{}", "=".repeat(60));
            let _ = writeln!(
                all_output,
                "=== Function: {} (entry @ {:#06x}) ===",
                func.name, func.entry_pc
            );
            let _ = writeln!(all_output, "\n{}", dataflow.summarize());
            let _ = writeln!(all_output, "{}", lifted.summarize());
            let _ = writeln!(all_output, "{}", structural.summarize());
        }

        all_output.push_str(&structural.pseudo_code(&func_cfg, Some(&mut lifted), Some(&sig)));
        all_output.push('\n');
    }

    // Clear the progress line
    if is_tty {
        eprint!("\r\x1b[K");
    }

    // Write all output at once
    print!("{}", all_output);

    Ok(())
}

/// Run the full decompilation pipeline on raw bytes and return pseudo-code output.
#[cfg(test)]
fn decompile_bytes(buffer: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let stripped = decoder::try_strip_metadata(buffer)?;
    let program = decoder::decode_spi(stripped).or_else(|_| decoder::decode_blob(stripped))?;
    let cfg = ControlFlowGraph::build(&program);
    let detected_functions = functions::detect_functions(&cfg);
    let call_graph = functions::build_call_graph(&cfg, &detected_functions, &program);

    let direct_call_patterns =
        functions::detect_direct_call_patterns(&cfg, &detected_functions, &program);

    let mut call_targets: HashMap<usize, String> = HashMap::new();
    let mut indirect_call_targets: HashMap<usize, String> = HashMap::new();
    let mut call_pattern_eliminated_pcs: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    for calls in call_graph.values() {
        for call in calls {
            call_targets.insert(call.callee_entry_pc, call.callee_name.clone());
            if let Some(block) = cfg.blocks.get(&call.caller_block_pc)
                && let Some((_, last_instr)) = block.instructions.last()
                && matches!(last_instr, Instruction::JumpInd { .. })
            {
                indirect_call_targets.insert(call.caller_block_pc, call.callee_name.clone());
            }
        }
    }
    for pat in &direct_call_patterns {
        call_targets.insert(pat.jump_target_pc, pat.callee_name.clone());
        call_pattern_eliminated_pcs.insert(pat.load_imm_pc);
    }

    let function_entry_pcs: std::collections::HashSet<usize> =
        detected_functions.iter().map(|f| f.entry_pc).collect();

    lifting::set_memory_base(program.memory_base);

    let mut output = String::new();
    for func in &detected_functions {
        let func_cfg = functions::build_function_cfg(&cfg, func);
        let dom_tree = structuring::DominatorTree::compute(&func_cfg);
        let dataflow = DataFlowAnalysis::analyze(&func_cfg);
        let mut lifted =
            lifting::LiftedProgram::analyze_with_dom_tree(&func_cfg, &dataflow, &dom_tree);
        lifted.call_targets = call_targets.clone();
        lifted.indirect_call_targets = indirect_call_targets.clone();
        lifted.memory_base = program.memory_base;

        // Detect epilogues and prologues
        let epilogues = functions::detect_epilogues(&func_cfg);
        let prologue_pcs = functions::detect_prologue(&func_cfg, func.entry_pc);
        for (block_pc, kind) in &epilogues {
            match kind {
                functions::EpilogueKind::Return { eliminated_pcs }
                | functions::EpilogueKind::Halt { eliminated_pcs } => {
                    for &pc in eliminated_pcs {
                        lifted.eliminated_pcs.insert(pc);
                    }
                }
            }
            lifted.epilogue_blocks.insert(*block_pc, kind.clone());
        }
        for &pc in &prologue_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        for &pc in &call_pattern_eliminated_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        let caller_block_pcs: HashSet<usize> = direct_call_patterns
            .iter()
            .flat_map(|p| [p.caller_block_pc, p.return_pc])
            .collect();
        for pat in &direct_call_patterns {
            if func.block_pcs.contains(&pat.jump_target_pc) && pat.callee_name != func.name {
                let mut queue = std::collections::VecDeque::new();
                queue.push_back(pat.jump_target_pc);
                while let Some(bp) = queue.pop_front() {
                    if lifted.suppressed_blocks.insert(bp)
                        && let Some(block) = func_cfg.blocks.get(&bp)
                    {
                        for &succ in &block.successors {
                            if !lifted.suppressed_blocks.contains(&succ)
                                && !caller_block_pcs.contains(&succ)
                            {
                                queue.push_back(succ);
                            }
                        }
                    }
                }
            }
        }

        let structural = structuring::StructuralAnalysis::analyze_with_dom_tree(
            &func_cfg,
            &program,
            dom_tree,
            function_entry_pcs.clone(),
        );

        let mut params: Vec<u8> = dataflow
            .live_in
            .get(&func.entry_pc)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        params.sort();
        let sig = structuring::FunctionSignature {
            name: func.name.clone(),
            params,
        };

        output.push_str(&structural.pseudo_code(&func_cfg, Some(&mut lifted), Some(&sig)));
        output.push('\n');
    }
    Ok(output)
}

fn write_cfg(cfg: &ControlFlowGraph, out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(out, "Entry PC: {:#06x}", cfg.entry_pc);
    let _ = writeln!(out, "Number of blocks: {}", cfg.blocks.len());

    let mut block_pcs: Vec<usize> = cfg.blocks.keys().copied().collect();
    block_pcs.sort();

    for block_pc in block_pcs {
        if let Some(block) = cfg.blocks.get(&block_pc) {
            let _ = writeln!(out, "\nBlock @ {:#06x} - {:#06x}:", block.start_pc, block.end_pc);
            for (pc, instr) in &block.instructions {
                let _ = writeln!(out, "    {:#06x}: {:?}", pc, instr);
            }

            if !block.successors.is_empty() {
                let succs: Vec<String> = block.successors.iter().map(|s| format!("{:#06x}", s)).collect();
                let _ = writeln!(out, "  Successors: {}", succs.join(", "));
            } else {
                let _ = writeln!(out, "  Successors: (none)");
            }

            if !block.predecessors.is_empty() {
                let preds: Vec<String> = block.predecessors.iter().map(|p| format!("{:#06x}", p)).collect();
                let _ = writeln!(out, "  Predecessors: {}", preds.join(", "));
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_fibonacci_full_pipeline() {
        let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
            .expect("fibonacci.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        // Should produce at least one function
        assert!(
            output.contains("fn "),
            "Output should contain function definitions: {}",
            output
        );
        // Should have control flow
        assert!(
            output.contains("while") || output.contains("for") || output.contains("if"),
            "Fibonacci should contain loops or branches: {}",
            output
        );
        // Should have return
        assert!(
            output.contains("return"),
            "Functions should have return statements: {}",
            output
        );
    }

    #[test]
    fn test_br_table_full_pipeline() {
        let buffer = std::fs::read("examples/compiled/br-table.pvm")
            .expect("br-table.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        // br-table programs should produce switch/case statements
        assert!(
            output.contains("switch") || output.contains("fn "),
            "br-table should produce structured output: {}",
            output
        );
    }

    #[test]
    fn test_simple_add_full_pipeline() {
        let buffer = std::fs::read("examples/compiled/simple-add.pvm")
            .expect("simple-add.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        // Should produce a main function with the addition result (42 + 100 = 142)
        assert!(
            output.contains("fn main"),
            "Output should contain main function: {}",
            output
        );
        assert!(
            output.contains("142"),
            "Output should contain the computed constant 142 (42 + 100): {}",
            output
        );
    }

    #[test]
    fn test_all_fixtures_decompile_without_panic() {
        let fixtures = [
            "examples/compiled/fibonacci.pvm",
            "examples/compiled/br-table.pvm",
            "examples/compiled/as-fibonacci.pvm",
            "examples/compiled/as-tests-control-flow.pvm",
            "examples/compiled/life-init-test.pvm",
            "examples/compiled/life-simple.pvm",
            "examples/compiled/simple-add.pvm",
            "examples/compiled/pvm.jam",
            "examples/compiled/ananas-compiler.jam",
        ];

        for fixture in &fixtures {
            let buffer = match std::fs::read(fixture) {
                Ok(b) => b,
                Err(_) => continue, // skip missing fixtures
            };
            let result = decompile_bytes(&buffer);
            assert!(
                result.is_ok(),
                "Fixture {} should decompile without error: {:?}",
                fixture,
                result.err()
            );
            let output = result.unwrap();
            assert!(
                !output.is_empty(),
                "Fixture {} should produce non-empty output",
                fixture
            );
        }
    }
}
