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
mod ir;
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

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTIONS] <file.pvm>", program);
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -v, --verbose  Show CFG, dataflow, and structural analysis");
    eprintln!("      --debug    Show raw instructions and all diagnostics");
    eprintln!("  -V, --version  Show version");
    eprintln!("  -h, --help     Show this help message");
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
            "-V" | "--version" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                return Ok(());
            }
            _ => {
                if arg.starts_with('-') {
                    eprintln!("Unknown option: {}", arg);
                    print_usage(&args[0]);
                    std::process::exit(2);
                }
                if filename.is_some() {
                    eprintln!("Only one input file can be provided");
                    print_usage(&args[0]);
                    std::process::exit(2);
                }
                filename = Some(arg.clone());
            }
        }
    }

    let filename = match filename {
        Some(f) => f,
        None => {
            print_usage(&args[0]);
            std::process::exit(2);
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
    let detected_functions =
        prune_unreachable_trivial_functions(&cfg, &program, detect_functions(&cfg));
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
    // Build exact direct-call mapping: Jump PC → callee name.
    let mut direct_call_sites: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    // PCs to eliminate from output (e.g., LoadImm64 setting return address in call patterns)
    let mut call_pattern_eliminated_pcs: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    for calls in call_graph.values() {
        for call in calls {
            call_targets.insert(call.callee_entry_pc, call.callee_name.clone());
        }
    }
    // Add direct call pattern sites: map Jump instruction PC to callee name.
    for pat in &direct_call_patterns {
        direct_call_sites.insert(pat.jump_pc, pat.callee_name.clone());
        call_pattern_eliminated_pcs.insert(pat.load_imm_pc);
    }

    // Compute function entry PCs for dispatch switch classification
    let function_entry_pcs: std::collections::HashSet<usize> =
        detected_functions.iter().map(|f| f.entry_pc).collect();

    // Precompute per-function CFG/dataflow once and collect parameter registers
    // for explicit call argument rendering.
    let mut function_cfgs: HashMap<usize, ControlFlowGraph> = HashMap::new();
    let mut function_dataflow: HashMap<usize, DataFlowAnalysis> = HashMap::new();
    let mut function_params_by_name: HashMap<String, Vec<u8>> = HashMap::new();
    for func in &detected_functions {
        let func_cfg = build_function_cfg(&cfg, func);
        let dataflow = DataFlowAnalysis::analyze(&func_cfg);
        let mut params: Vec<u8> = dataflow
            .live_in
            .get(&func.entry_pc)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        params.sort();
        function_params_by_name.insert(func.name.clone(), params);
        function_dataflow.insert(func.entry_pc, dataflow);
        function_cfgs.insert(func.entry_pc, func_cfg);
    }

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
            progress("preparing analysis...");
        }

        let func_cfg = function_cfgs
            .remove(&func.entry_pc)
            .unwrap_or_else(|| build_function_cfg(&cfg, func));

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Computing dominator tree...");
        } else {
            progress("dominator tree...");
        }
        let dom_tree = DominatorTree::compute(&func_cfg);

        let dataflow = function_dataflow
            .remove(&func.entry_pc)
            .unwrap_or_else(|| DataFlowAnalysis::analyze(&func_cfg));

        if verbosity >= Verbosity::Verbose {
            eprintln!("  Lifting expressions...");
        } else {
            progress("lifting expressions...");
        }
        let mut lifted = LiftedProgram::analyze_with_dom_tree(&func_cfg, &dataflow, &dom_tree);
        lifted.call_targets = call_targets.clone();
        lifted.direct_call_sites = direct_call_sites.clone();
        lifted.call_param_regs = function_params_by_name.clone();
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
        let redundant_halt_setup_pcs = redundant_halt_setup_pcs_for_function(&func_cfg, &epilogues);
        for pc in redundant_halt_setup_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        // Eliminate LoadImm64 instructions from call patterns (return address setup)
        for &pc in &call_pattern_eliminated_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        // Eliminate redundant constant call-setup writes for direct-call patterns
        // (e.g., trampoline selector registers) when they are not callee params
        // and not live after the call returns.
        let redundant_call_setup_pcs = redundant_call_setup_pcs_for_function(
            &func_cfg,
            &dataflow,
            &direct_call_patterns,
            &function_params_by_name,
        );
        for pc in redundant_call_setup_pcs {
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
        let params = function_params_by_name
            .get(&func.name)
            .cloned()
            .unwrap_or_default();
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

        all_output.push_str(&structural.pseudo_code(&func_cfg, Some(&lifted), Some(&sig)));
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
    let detected_functions =
        prune_unreachable_trivial_functions(&cfg, &program, functions::detect_functions(&cfg));
    let call_graph = functions::build_call_graph(&cfg, &detected_functions, &program);

    let direct_call_patterns =
        functions::detect_direct_call_patterns(&cfg, &detected_functions, &program);

    let mut call_targets: HashMap<usize, String> = HashMap::new();
    let mut direct_call_sites: HashMap<usize, String> = HashMap::new();
    let mut call_pattern_eliminated_pcs: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    for calls in call_graph.values() {
        for call in calls {
            call_targets.insert(call.callee_entry_pc, call.callee_name.clone());
        }
    }
    for pat in &direct_call_patterns {
        direct_call_sites.insert(pat.jump_pc, pat.callee_name.clone());
        call_pattern_eliminated_pcs.insert(pat.load_imm_pc);
    }

    let function_entry_pcs: std::collections::HashSet<usize> =
        detected_functions.iter().map(|f| f.entry_pc).collect();

    let mut function_cfgs: HashMap<usize, ControlFlowGraph> = HashMap::new();
    let mut function_dataflow: HashMap<usize, DataFlowAnalysis> = HashMap::new();
    let mut function_params_by_name: HashMap<String, Vec<u8>> = HashMap::new();
    for func in &detected_functions {
        let func_cfg = functions::build_function_cfg(&cfg, func);
        let dataflow = DataFlowAnalysis::analyze(&func_cfg);
        let mut params: Vec<u8> = dataflow
            .live_in
            .get(&func.entry_pc)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        params.sort();
        function_params_by_name.insert(func.name.clone(), params);
        function_dataflow.insert(func.entry_pc, dataflow);
        function_cfgs.insert(func.entry_pc, func_cfg);
    }

    let mut output = String::new();
    for func in &detected_functions {
        let func_cfg = function_cfgs
            .remove(&func.entry_pc)
            .unwrap_or_else(|| functions::build_function_cfg(&cfg, func));
        let dom_tree = structuring::DominatorTree::compute(&func_cfg);
        let dataflow = function_dataflow
            .remove(&func.entry_pc)
            .unwrap_or_else(|| DataFlowAnalysis::analyze(&func_cfg));
        let mut lifted =
            lifting::LiftedProgram::analyze_with_dom_tree(&func_cfg, &dataflow, &dom_tree);
        lifted.call_targets = call_targets.clone();
        lifted.direct_call_sites = direct_call_sites.clone();
        lifted.call_param_regs = function_params_by_name.clone();
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
        let redundant_halt_setup_pcs = redundant_halt_setup_pcs_for_function(&func_cfg, &epilogues);
        for pc in redundant_halt_setup_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        for &pc in &call_pattern_eliminated_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        let redundant_call_setup_pcs = redundant_call_setup_pcs_for_function(
            &func_cfg,
            &dataflow,
            &direct_call_patterns,
            &function_params_by_name,
        );
        for pc in redundant_call_setup_pcs {
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

        let params = function_params_by_name
            .get(&func.name)
            .cloned()
            .unwrap_or_default();
        let sig = structuring::FunctionSignature {
            name: func.name.clone(),
            params,
        };

        output.push_str(&structural.pseudo_code(&func_cfg, Some(&lifted), Some(&sig)));
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
            let _ = writeln!(
                out,
                "\nBlock @ {:#06x} - {:#06x}:",
                block.start_pc, block.end_pc
            );
            for (pc, instr) in &block.instructions {
                let _ = writeln!(out, "    {:#06x}: {:?}", pc, instr);
            }

            if !block.successors.is_empty() {
                let succs: Vec<String> = block
                    .successors
                    .iter()
                    .map(|s| format!("{:#06x}", s))
                    .collect();
                let _ = writeln!(out, "  Successors: {}", succs.join(", "));
            } else {
                let _ = writeln!(out, "  Successors: (none)");
            }

            if !block.predecessors.is_empty() {
                let preds: Vec<String> = block
                    .predecessors
                    .iter()
                    .map(|p| format!("{:#06x}", p))
                    .collect();
                let _ = writeln!(out, "  Predecessors: {}", preds.join(", "));
            }
        }
    }
}

fn prune_unreachable_trivial_functions(
    cfg: &ControlFlowGraph,
    program: &decoder::DecodedProgram,
    detected_functions: Vec<functions::Function>,
) -> Vec<functions::Function> {
    let jump_table_targets: HashSet<usize> =
        program.jump_table.iter().map(|&pc| pc as usize).collect();

    detected_functions
        .into_iter()
        .filter(|func| {
            if func.entry_pc == cfg.entry_pc || jump_table_targets.contains(&func.entry_pc) {
                return true;
            }

            let has_any_predecessor = cfg
                .blocks
                .get(&func.entry_pc)
                .is_some_and(|block| !block.predecessors.is_empty());
            if has_any_predecessor {
                return true;
            }

            !is_trivial_unreachable_stub(cfg, func)
        })
        .collect()
}

fn is_trivial_unreachable_stub(cfg: &ControlFlowGraph, func: &functions::Function) -> bool {
    if func.block_pcs.is_empty() {
        return true;
    }

    for block_pc in &func.block_pcs {
        let Some(block) = cfg.blocks.get(block_pc) else {
            continue;
        };
        for (_, instr) in &block.instructions {
            if !matches!(instr, Instruction::Trap | Instruction::Fallthrough) {
                return false;
            }
        }
    }

    true
}

fn redundant_call_setup_pcs_for_function(
    func_cfg: &ControlFlowGraph,
    dataflow: &DataFlowAnalysis,
    direct_call_patterns: &[functions::DirectCallPattern],
    function_params_by_name: &HashMap<String, Vec<u8>>,
) -> HashSet<usize> {
    let mut eliminated: HashSet<usize> = HashSet::new();

    for pat in direct_call_patterns {
        let Some(block) = func_cfg.blocks.get(&pat.caller_block_pc) else {
            continue;
        };
        let Some(jump_idx) = block
            .instructions
            .iter()
            .position(|(pc, _)| *pc == pat.jump_pc)
        else {
            continue;
        };

        let param_regs: HashSet<u8> = function_params_by_name
            .get(&pat.callee_name)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let live_after: HashSet<u8> = dataflow
            .live_in
            .get(&pat.return_pc)
            .cloned()
            .unwrap_or_default();

        for idx in 0..jump_idx {
            let (pc, instr) = &block.instructions[idx];

            // Return-address setup is handled separately.
            if *pc == pat.load_imm_pc {
                continue;
            }
            // Restrict to literal constant setup writes.
            if !matches!(
                instr,
                Instruction::LoadImm { .. } | Instruction::LoadImm64 { .. }
            ) {
                continue;
            }

            let shape = crate::instruction::InstructionShape::classify(instr);
            let Some(reg) = shape.def_reg() else {
                continue;
            };
            if reg == 0 || param_regs.contains(&reg) || live_after.contains(&reg) {
                continue;
            }

            // Keep assignments that feed other instructions before the call.
            let mut used_before_kill = false;
            for (_, next_instr) in &block.instructions[idx + 1..=jump_idx] {
                let next_shape = crate::instruction::InstructionShape::classify(next_instr);
                let (defs, uses) = next_shape.def_use();
                if uses.contains(&reg) {
                    used_before_kill = true;
                    break;
                }
                if defs.contains(&reg) {
                    break;
                }
            }
            if used_before_kill {
                continue;
            }

            eliminated.insert(*pc);
        }
    }

    eliminated
}

fn redundant_halt_setup_pcs_for_function(
    func_cfg: &ControlFlowGraph,
    epilogues: &HashMap<usize, functions::EpilogueKind>,
) -> HashSet<usize> {
    let mut eliminated = HashSet::new();

    for (&block_pc, kind) in epilogues {
        let functions::EpilogueKind::Halt {
            eliminated_pcs: halt_epilogue_pcs,
        } = kind
        else {
            continue;
        };
        let Some(block) = func_cfg.blocks.get(&block_pc) else {
            continue;
        };

        let halt_epilogue_set: HashSet<usize> = halt_epilogue_pcs.iter().copied().collect();
        let mut needed_regs: HashSet<u8> = HashSet::new();

        for (pc, instr) in block.instructions.iter().rev() {
            if halt_epilogue_set.contains(pc) {
                continue;
            }

            let shape = crate::instruction::InstructionShape::classify(instr);
            let (defs, uses) = shape.def_use();

            if is_halt_setup_side_effecting(&shape) {
                for reg in defs {
                    needed_regs.remove(&reg);
                }
                needed_regs.extend(uses);
                continue;
            }

            let defs_needed = defs.iter().any(|reg| needed_regs.contains(reg));
            if !defs_needed && is_eliminable_halt_setup_shape(&shape) {
                eliminated.insert(*pc);
                continue;
            }

            for reg in defs {
                needed_regs.remove(&reg);
            }
            needed_regs.extend(uses);
        }
    }

    eliminated
}

fn is_halt_setup_side_effecting(shape: &crate::instruction::InstructionShape) -> bool {
    use crate::instruction::InstructionShape;
    matches!(
        shape,
        InstructionShape::Store { .. }
            | InstructionShape::StoreAbsolute { .. }
            | InstructionShape::StoreImm { .. }
            | InstructionShape::StoreImmInd { .. }
            | InstructionShape::Jump { .. }
            | InstructionShape::JumpInd { .. }
            | InstructionShape::LoadImmJump { .. }
            | InstructionShape::LoadImmJumpInd { .. }
            | InstructionShape::BranchImm { .. }
            | InstructionShape::BranchReg { .. }
            | InstructionShape::Ecalli { .. }
            | InstructionShape::Unknown { .. }
            | InstructionShape::NoOp { name: "trap" }
    )
}

fn is_eliminable_halt_setup_shape(shape: &crate::instruction::InstructionShape) -> bool {
    use crate::instruction::InstructionShape;
    matches!(
        shape,
        InstructionShape::NoOp {
            name: "fallthrough"
        } | InstructionShape::LoadImm { .. }
            | InstructionShape::BinReg { .. }
            | InstructionShape::BinImm { .. }
            | InstructionShape::BinImmRev { .. }
            | InstructionShape::Unary { .. }
            | InstructionShape::Load { .. }
            | InstructionShape::LoadAbsolute { .. }
            | InstructionShape::CmovReg { .. }
            | InstructionShape::CmovImm { .. }
    )
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn count_non_signature_main_calls(output: &str) -> usize {
        output
            .lines()
            .filter(|line| !line.trim_start().starts_with("fn main("))
            .map(|line| line.matches("main()").count())
            .sum()
    }

    fn condition_lhs_var(line: &str) -> Option<String> {
        let trimmed = line.trim();
        let cond = trimmed.strip_prefix("if (")?;
        let end = cond.find(')')?;
        let lhs = cond[..end]
            .split_whitespace()
            .next()?
            .trim_start_matches('!')
            .trim_start_matches('(')
            .trim_end_matches(')');
        if lhs.starts_with("var_") || lhs.starts_with("ptr_") || lhs.starts_with("cond_") {
            Some(lhs.to_string())
        } else {
            None
        }
    }

    fn output_defines_variable(output: &str, var: &str) -> bool {
        let sig_head = format!("({}: ", var);
        let sig_mid = format!(", {}: ", var);
        let let_stmt = format!("let {} ", var);
        let assign = format!("{} =", var);
        output.lines().any(|line| {
            let trimmed = line.trim_start();
            line.contains(&sig_head)
                || line.contains(&sig_mid)
                || trimmed.starts_with(&let_stmt)
                || trimmed.starts_with(&assign)
        })
    }

    fn assert_no_placeholders_or_raw_jumps(output: &str, fixture_name: &str) {
        assert!(
            !output.contains("if (...)"),
            "{} should not contain placeholder conditions: {}",
            fixture_name,
            output
        );
        assert!(
            !output.contains("while (...)"),
            "{} should not contain placeholder loop conditions: {}",
            fixture_name,
            output
        );
        assert!(
            !output.contains("jump <"),
            "{} should not contain raw jump offsets: {}",
            fixture_name,
            output
        );
    }

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
        // Should have a function terminator
        assert!(
            output.contains("return") || output.contains("halt()"),
            "Functions should have return or halt terminators: {}",
            output
        );
    }

    #[test]
    fn test_fibonacci_regression_elides_redundant_entry_goto_and_dead_stub_function() {
        let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
            .expect("fibonacci.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        assert!(
            !output.contains("goto block_000a;"),
            "Linear entry jumps to immediately emitted blocks should be elided: {}",
            output
        );
        assert!(
            !output.contains("fn func_0()"),
            "Unreachable trap-only stubs should not be emitted as functions: {}",
            output
        );
        assert!(
            !output
                .lines()
                .any(|line| line.trim_start().starts_with("block_")),
            "Unreferenced block labels should be pruned from structured output: {}",
            output
        );
    }

    #[test]
    fn test_fibonacci_regression_inverts_loop_condition_and_elides_forwarder_jump() {
        let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
            .expect("fibonacci.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        assert!(
            output.contains("while (ptr_0_80 <u ptr_0_56)"),
            "Loop header exit-branch conditions should render as continue conditions: {}",
            output
        );
        assert!(
            !output.contains("goto block_00b9;"),
            "Loop forwarder jumps to the next body block should be elided: {}",
            output
        );
    }

    #[test]
    fn test_fibonacci_regression_elides_dead_pre_halt_setup_noise() {
        let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
            .expect("fibonacci.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        let lines: Vec<&str> = output.lines().collect();
        let halt_idx = lines
            .iter()
            .position(|line| line.trim() == "halt()")
            .expect("fibonacci output should contain halt()");
        let prev_non_empty = lines[..halt_idx]
            .iter()
            .rev()
            .find(|line| !line.trim().is_empty())
            .copied()
            .unwrap_or("");

        assert!(
            !prev_non_empty.trim_start().starts_with("let "),
            "Dead temporary setup immediately before halt should be eliminated: {}",
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
    fn test_br_table_condition_selectors_are_defined() {
        let buffer = std::fs::read("examples/compiled/br-table.pvm")
            .expect("br-table.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        assert_no_placeholders_or_raw_jumps(&output, "br-table");

        for line in output.lines() {
            let Some(var) = condition_lhs_var(line) else {
                continue;
            };
            assert!(
                output_defines_variable(&output, &var),
                "br-table condition variable `{}` should remain defined: {}",
                var,
                output
            );
        }

        // Golden-style checks for selector definition/flow.
        assert!(
            output.contains("let var_1 = u32[r7]"),
            "br-table should keep selector definition: {}",
            output
        );
        assert!(
            output.contains("if (var_1 == 0)") && output.contains("if (var_1 == 2)"),
            "br-table should preserve selector-based branching flow: {}",
            output
        );
    }

    #[test]
    fn test_simple_add_full_pipeline() {
        let buffer = std::fs::read("examples/compiled/simple-add.pvm")
            .expect("simple-add.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        // Should produce a main function and preserve the explicit addition operation.
        assert!(
            output.contains("fn main"),
            "Output should contain main function: {}",
            output
        );
        assert!(
            output.contains("42 + 100") || output.contains("100 + 42"),
            "Output should contain explicit addition (42 + 100): {}",
            output
        );
        assert!(
            output.contains("r2 ="),
            "Dead temporary result should render as register assignment: {}",
            output
        );
        assert!(
            !output.contains("let var_2 ="),
            "simple-add should not declare dead temporary as synthetic variable: {}",
            output
        );
    }

    #[test]
    fn test_life_simple_no_false_main_self_call() {
        let buffer = std::fs::read("examples/compiled/life-simple.pvm")
            .expect("life-simple.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        assert_no_placeholders_or_raw_jumps(&output, "life-simple");

        let main_calls = count_non_signature_main_calls(&output);
        assert_eq!(
            main_calls, 0,
            "life-simple should not contain false main() self-calls: {}",
            output
        );
    }

    #[test]
    fn test_ananas_no_false_main_self_call() {
        let buffer =
            std::fs::read("examples/compiled/ananas.pvm").expect("ananas.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        let main_calls = count_non_signature_main_calls(&output);
        assert_eq!(
            main_calls, 0,
            "ananas should not contain false main() self-calls: {}",
            output
        );
    }

    #[test]
    fn test_ananas_trampoline_selector_setup_elided() {
        let buffer =
            std::fs::read("examples/compiled/ananas.pvm").expect("ananas.pvm fixture should exist");
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        assert!(
            output.contains("func_13(ptr_12, r7)"),
            "Expected explicit call arguments for func_13: {}",
            output
        );
        assert!(
            !output.contains("let var_210 = 17"),
            "Redundant trampoline selector constant should be elided: {}",
            output
        );
    }

    #[test]
    fn test_redundant_call_setup_elimination_is_precise() {
        use crate::cfg::build_test_cfg;

        // Caller block setup:
        // - r9 constant: redundant trampoline selector-like setup (should be removed)
        // - r7 constant: callee parameter (must be kept)
        // - r6 constant: live after return (must be kept)
        // - r0 constant: return address setup (handled separately, must be ignored here)
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 9, value: 17 }),
                        (4, Instruction::LoadImm { reg: 7, value: 55 }),
                        (8, Instruction::LoadImm { reg: 6, value: 9 }),
                        (12, Instruction::LoadImm64 { reg: 0, value: 2 }),
                        (16, Instruction::Jump { offset: 84 }),
                    ],
                    vec![20],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::Add32 {
                                dst: 2,
                                src1: 6,
                                src2: 7,
                            },
                        ),
                        (24, Instruction::Trap),
                    ],
                    vec![],
                ),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);

        let patterns = vec![crate::functions::DirectCallPattern {
            caller_block_pc: 0,
            load_imm_pc: 12,
            jump_pc: 16,
            jump_target_pc: 100,
            return_pc: 20,
            callee_name: "callee".to_string(),
        }];

        let mut params = HashMap::new();
        params.insert("callee".to_string(), vec![7]);

        let eliminated = redundant_call_setup_pcs_for_function(&cfg, &dataflow, &patterns, &params);

        assert!(
            eliminated.contains(&0),
            "Non-param, non-live trampoline setup constant should be eliminated"
        );
        assert!(
            !eliminated.contains(&4),
            "Callee parameter setup constant must be preserved"
        );
        assert!(
            !eliminated.contains(&8),
            "Constant for register live after return must be preserved"
        );
        assert!(
            !eliminated.contains(&12),
            "r0 return-address setup must be left to call-pattern elimination"
        );
    }

    #[test]
    fn test_redundant_halt_setup_elimination_is_precise() {
        use crate::cfg::build_test_cfg;

        // Halt block setup:
        // - r4 feeds a store side effect (must be kept)
        // - r5/r6 chain is dead and should be removed
        // - r7 constant after side-effect is dead and should be removed
        // - final LoadImm r2 + JumpInd r2 are epilogue instructions (handled by epilogue detection)
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 4, value: 10 }),
                    (4, Instruction::LoadImm { reg: 5, value: 1 }),
                    (
                        8,
                        Instruction::Add32 {
                            dst: 6,
                            src1: 5,
                            src2: 5,
                        },
                    ),
                    (
                        12,
                        Instruction::StoreIndU64 {
                            base: 1,
                            src: 4,
                            offset: 0,
                        },
                    ),
                    (16, Instruction::LoadImm { reg: 7, value: 99 }),
                    (
                        20,
                        Instruction::LoadImm {
                            reg: 2,
                            value: -0x10000,
                        },
                    ),
                    (24, Instruction::JumpInd { reg: 2, offset: 0 }),
                ],
                vec![],
            )],
        );

        let epilogues = detect_epilogues(&cfg);
        let eliminated = redundant_halt_setup_pcs_for_function(&cfg, &epilogues);

        assert!(
            !eliminated.contains(&0),
            "setup feeding a side-effecting store must be preserved"
        );
        assert!(
            eliminated.contains(&4) && eliminated.contains(&8),
            "dead pure setup chain should be eliminated"
        );
        assert!(
            !eliminated.contains(&12),
            "side-effecting store must be preserved"
        );
        assert!(
            eliminated.contains(&16),
            "dead pure setup after side effects should be eliminated"
        );
        assert!(
            !eliminated.contains(&20) && !eliminated.contains(&24),
            "halt epilogue instructions are handled by epilogue detection, not this pass"
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

    #[test]
    fn test_jam_fuzzy_service_subset_without_placeholders() {
        let buffer = match std::fs::read("examples/compiled/pvm.jam") {
            Ok(b) => b,
            Err(_) => return, // Skip when fixture is unavailable in this environment.
        };
        let output = decompile_bytes(&buffer).expect("decompilation should succeed");

        // Keep this focused to a stable prefix so it acts like a targeted golden subset.
        let subset = output.lines().take(600).collect::<Vec<_>>().join("\n");
        assert!(
            !subset.contains("if (...)") && !subset.contains("while (...)"),
            "jam-fuzzy-service subset should be placeholder-free: {}",
            subset
        );
        assert!(
            !subset.contains("jump <"),
            "jam-fuzzy-service subset should not contain raw jumps: {}",
            subset
        );
    }
}
