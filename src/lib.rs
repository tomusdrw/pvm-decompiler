pub mod cfg;
pub mod dataflow;
pub mod decoder;
pub mod functions;
pub mod instruction;
pub mod ir;
pub mod lifting;
pub mod llvm_lift;
pub mod structuring;
pub mod varint;

#[cfg(feature = "native")]
pub mod decompile;
#[cfg(feature = "native")]
pub mod llm_refine;

#[cfg(feature = "wasm")]
pub mod wasm;

use std::collections::{HashMap, HashSet};

use cfg::ControlFlowGraph;
use dataflow::DataFlowAnalysis;
use functions::{
    build_call_graph, build_function_cfg, detect_direct_call_patterns, detect_epilogues,
    detect_functions, detect_heap_alloc_pattern, detect_prologue,
};
use lifting::{Expression, LiftedProgram};
use structuring::{DominatorTree, FunctionSignature, StructuralAnalysis};
use wasm_pvm::pvm::Instruction;

/// Structured output of a decompilation run.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(serde::Serialize))]
pub struct DecompileOutput {
    /// The pseudo-code output as a string.
    pub pseudo_code: String,
    /// Number of functions detected in the program.
    pub function_count: usize,
    /// Detected function names and their entry addresses.
    pub functions: Vec<FunctionInfo>,
    /// Warnings emitted during decompilation.
    pub warnings: Vec<String>,
}

/// Information about a detected function.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(serde::Serialize))]
pub struct FunctionInfo {
    pub name: String,
    pub entry_pc: usize,
    pub block_count: usize,
    pub param_count: usize,
}

/// Decompile raw PVM bytes to pseudo-code.
///
/// Accepts SPI format, raw blob, or metadata-prefixed binaries; auto-detects the format.
/// Returns structured output with pseudo-code and metadata, or an error message.
pub fn decompile_to_pseudocode(bytes: &[u8]) -> Result<DecompileOutput, String> {
    let stripped = decoder::try_strip_metadata(bytes).map_err(|e| e.to_string())?;
    let program = decoder::decode_spi(stripped)
        .or_else(|_| decoder::decode_blob(stripped))
        .map_err(|e| e.to_string())?;

    let mut warnings = Vec::new();

    // Collect unknown opcode warnings
    let mut unknown_opcodes: HashMap<u8, usize> = HashMap::new();
    for (_, instr) in &program.instructions {
        if let Instruction::Unknown { opcode, .. } = instr {
            *unknown_opcodes.entry(*opcode).or_default() += 1;
        }
    }
    if !unknown_opcodes.is_empty() {
        let mut sorted: Vec<_> = unknown_opcodes.iter().collect();
        sorted.sort_by_key(|(op, _)| **op);
        for (opcode, count) in sorted {
            warnings.push(format!(
                "Unknown opcode {:#04x}: {} occurrence(s)",
                opcode, count
            ));
        }
    }

    let cfg = ControlFlowGraph::build(&program);
    let detected_functions =
        prune_unreachable_trivial_functions(&cfg, &program, detect_functions(&cfg));
    let call_graph = build_call_graph(&cfg, &detected_functions, &program);

    let direct_call_patterns = detect_direct_call_patterns(&cfg, &detected_functions, &program);

    let mut call_targets: HashMap<usize, String> = HashMap::new();
    let mut direct_call_sites: HashMap<usize, String> = HashMap::new();
    let mut call_pattern_eliminated_pcs: HashSet<usize> = HashSet::new();
    for calls in call_graph.values() {
        for call in calls {
            call_targets.insert(call.callee_entry_pc, call.callee_name.clone());
        }
    }
    for pat in &direct_call_patterns {
        direct_call_sites.insert(pat.jump_pc, pat.callee_name.clone());
        call_pattern_eliminated_pcs.insert(pat.load_imm_pc);
    }

    let function_entry_pcs: HashSet<usize> =
        detected_functions.iter().map(|f| f.entry_pc).collect();

    let mut function_cfgs: HashMap<usize, ControlFlowGraph> = HashMap::new();
    let mut function_dataflow: HashMap<usize, DataFlowAnalysis> = HashMap::new();
    let mut function_params_by_name: HashMap<String, Vec<u8>> = HashMap::new();
    for func in &detected_functions {
        let func_cfg = build_function_cfg(&cfg, func, &direct_call_patterns, &program.jump_table);
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

    let mut function_infos = Vec::new();
    let mut output = String::new();
    for func in &detected_functions {
        let func_cfg = function_cfgs.remove(&func.entry_pc).unwrap_or_else(|| {
            build_function_cfg(&cfg, func, &direct_call_patterns, &program.jump_table)
        });
        let dom_tree = DominatorTree::compute(&func_cfg);
        let dataflow = function_dataflow
            .remove(&func.entry_pc)
            .unwrap_or_else(|| DataFlowAnalysis::analyze(&func_cfg));
        let mut lifted = LiftedProgram::analyze_with_dom_tree(&func_cfg, &dataflow, &dom_tree);
        lifted.call_targets = call_targets.clone();
        lifted.direct_call_sites = direct_call_sites.clone();
        lifted.call_param_regs = function_params_by_name.clone();
        lifted.memory_base = program.memory_base;

        // Detect epilogues and prologues
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
        let jump_table_pcs: HashSet<usize> =
            program.jump_table.iter().map(|&e| e as usize).collect();
        let mut suppression_stop_pcs: HashSet<usize> = direct_call_patterns
            .iter()
            .flat_map(|p| [p.caller_block_pc, p.return_pc])
            .collect();
        for &bp in func.block_pcs.iter() {
            if bp != func.entry_pc && jump_table_pcs.contains(&bp) {
                if let Some(block) = func_cfg.blocks.get(&bp) {
                    if block.predecessors.iter().all(|&pred| {
                        direct_call_patterns
                            .iter()
                            .any(|pat| pat.jump_target_pc == pred)
                    }) {
                        suppression_stop_pcs.insert(bp);
                    }
                }
            }
        }
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
                                && !suppression_stop_pcs.contains(&succ)
                            {
                                queue.push_back(succ);
                            }
                        }
                    }
                }
            }
        }
        unsuppress_blocks_with_live_incoming_edges(&mut lifted, &func_cfg, &direct_call_patterns);

        apply_heap_alloc_suppression(&mut lifted, &func_cfg, func.entry_pc, program.memory_base);

        let structural = StructuralAnalysis::analyze_with_dom_tree(
            &func_cfg,
            &program,
            dom_tree,
            function_entry_pcs.clone(),
        );

        let params = function_params_by_name
            .get(&func.name)
            .cloned()
            .unwrap_or_default();
        let sig = FunctionSignature {
            name: func.name.clone(),
            params: params.clone(),
        };

        function_infos.push(FunctionInfo {
            name: func.name.clone(),
            entry_pc: func.entry_pc,
            block_count: func.block_pcs.len(),
            param_count: params.len(),
        });

        output.push_str(&structural.pseudo_code(&func_cfg, Some(&lifted), Some(&sig)));
        output.push('\n');
    }

    Ok(DecompileOutput {
        pseudo_code: output,
        function_count: detected_functions.len(),
        functions: function_infos,
        warnings,
    })
}

// --- Helper functions moved from main.rs ---

pub fn prune_unreachable_trivial_functions(
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

pub fn redundant_call_setup_pcs_for_function(
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

            if *pc == pat.load_imm_pc {
                continue;
            }
            if !matches!(
                instr,
                Instruction::LoadImm { .. } | Instruction::LoadImm64 { .. }
            ) {
                continue;
            }

            let shape = instruction::InstructionShape::classify(instr);
            let Some(reg) = shape.def_reg() else {
                continue;
            };
            if reg == 0 || param_regs.contains(&reg) || live_after.contains(&reg) {
                continue;
            }

            let mut used_before_kill = false;
            for (_, next_instr) in &block.instructions[idx + 1..=jump_idx] {
                let next_shape = instruction::InstructionShape::classify(next_instr);
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

pub fn redundant_halt_setup_pcs_for_function(
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

            let shape = instruction::InstructionShape::classify(instr);
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

pub fn apply_heap_alloc_suppression(
    lifted: &mut LiftedProgram,
    func_cfg: &ControlFlowGraph,
    func_entry_pc: usize,
    memory_base: Option<u64>,
) {
    if let Some(heap_alloc) = detect_heap_alloc_pattern(func_cfg, func_entry_pc, memory_base) {
        for &pc in &heap_alloc.eliminated_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        for &pc in &heap_alloc.heap_ptr_arithmetic_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        for &pc in &heap_alloc.header_write_pcs {
            lifted.eliminated_pcs.insert(pc);
        }
        for &block_pc in &heap_alloc.sbrk_blocks {
            lifted.suppressed_blocks.insert(block_pc);
        }
        lifted.hidden_labels.insert(heap_alloc.convergence_block_pc);
        lifted.linear_memory_offset = heap_alloc.linear_memory_offset;

        let arith_pcs: HashSet<usize> =
            heap_alloc.heap_ptr_arithmetic_pcs.iter().copied().collect();
        let mut arith_vars: Vec<String> = Vec::new();
        for &pc in &heap_alloc.heap_ptr_arithmetic_pcs {
            if let Some(Expression::Store { base, offset, .. }) = lifted.expressions.get(&pc)
                && let Expression::Var(base_name) = base.as_ref()
                && let Some(name) = lifted.stack_vars.get(&(base_name.clone(), *offset))
            {
                arith_vars.push(name.clone());
            }
        }
        'outer: for var_name in &arith_vars {
            for (pc, expr) in &lifted.expressions {
                if arith_pcs.contains(pc) || lifted.eliminated_pcs.contains(pc) {
                    continue;
                }
                if expr_uses_var(expr, var_name) {
                    lifted.heap_alloc_data_ptr = Some(var_name.clone());
                    break 'outer;
                }
            }
        }

        lifted.heap_alloc = Some(heap_alloc);
    }
}

pub fn unsuppress_blocks_with_live_incoming_edges(
    lifted: &mut LiftedProgram,
    func_cfg: &ControlFlowGraph,
    direct_call_patterns: &[functions::DirectCallPattern],
) {
    if lifted.suppressed_blocks.is_empty() {
        return;
    }

    let allowed_call_edges: HashSet<(usize, usize)> = direct_call_patterns
        .iter()
        .map(|pat| (pat.caller_block_pc, pat.jump_target_pc))
        .collect();

    let mut queue = std::collections::VecDeque::new();
    for &block_pc in &lifted.suppressed_blocks {
        let Some(block) = func_cfg.blocks.get(&block_pc) else {
            continue;
        };
        let has_live_incoming_edge = block.predecessors.iter().any(|pred| {
            !lifted.suppressed_blocks.contains(pred)
                && !allowed_call_edges.contains(&(*pred, block_pc))
        });
        if has_live_incoming_edge {
            queue.push_back(block_pc);
        }
    }

    while let Some(block_pc) = queue.pop_front() {
        if !lifted.suppressed_blocks.remove(&block_pc) {
            continue;
        }
        if let Some(block) = func_cfg.blocks.get(&block_pc) {
            for &succ in &block.successors {
                if lifted.suppressed_blocks.contains(&succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
}

fn is_halt_setup_side_effecting(shape: &instruction::InstructionShape) -> bool {
    use instruction::InstructionShape;
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

fn is_eliminable_halt_setup_shape(shape: &instruction::InstructionShape) -> bool {
    use instruction::InstructionShape;
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

/// Check if an expression tree references a variable by name.
pub fn expr_uses_var(expr: &Expression, name: &str) -> bool {
    match expr {
        Expression::Var(n) => n == name,
        Expression::BinOp { lhs, rhs, .. } => expr_uses_var(lhs, name) || expr_uses_var(rhs, name),
        Expression::UnaryOp { operand, .. } => expr_uses_var(operand, name),
        Expression::Load { base, .. } => expr_uses_var(base, name),
        Expression::Store { base, value, .. } => {
            expr_uses_var(base, name) || expr_uses_var(value, name)
        }
        Expression::Call { args, .. } => args.iter().any(|a| expr_uses_var(a, name)),
        Expression::Raw(text) => text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|tok| tok == name),
        Expression::Const(_) => false,
    }
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn test_decompile_to_pseudocode_fibonacci() {
        let buffer = std::fs::read("examples/compiled/fibonacci.pvm")
            .expect("fibonacci.pvm fixture should exist");
        let result = decompile_to_pseudocode(&buffer).expect("decompilation should succeed");

        assert!(!result.pseudo_code.is_empty());
        assert!(result.function_count > 0);
        assert!(!result.functions.is_empty());
        assert_eq!(result.function_count, result.functions.len());
        assert!(result.pseudo_code.contains("fn "));
    }

    #[test]
    fn test_decompile_to_pseudocode_returns_metadata() {
        let buffer = std::fs::read("examples/compiled/as-fibonacci.pvm")
            .expect("as-fibonacci.pvm fixture should exist");
        let result = decompile_to_pseudocode(&buffer).expect("decompilation should succeed");

        // Should have function info
        assert!(result.function_count >= 1);
        let main_func = result.functions.iter().find(|f| f.name == "main");
        assert!(main_func.is_some(), "Should detect a main function");
    }

    #[test]
    fn test_decompile_to_pseudocode_invalid_input() {
        let result = decompile_to_pseudocode(&[0xFF, 0xFF, 0xFF]);
        // Should either succeed with warnings or fail with an error message
        // (not panic)
        let _ = result;
    }

    #[test]
    fn test_decompile_to_pseudocode_empty_input() {
        let result = decompile_to_pseudocode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompile_to_pseudocode_all_fixtures() {
        let fixtures = [
            "examples/compiled/fibonacci.pvm",
            "examples/compiled/br-table.pvm",
            "examples/compiled/as-fibonacci.pvm",
            "examples/compiled/simple-add.pvm",
            "examples/compiled/host-call-log.pvm",
            "examples/compiled/pvm.jam",
        ];

        for fixture in &fixtures {
            let buffer = match std::fs::read(fixture) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let result = decompile_to_pseudocode(&buffer);
            assert!(
                result.is_ok(),
                "Fixture {} should decompile without error: {:?}",
                fixture,
                result.err()
            );
            let output = result.unwrap();
            assert!(
                !output.pseudo_code.is_empty(),
                "Fixture {} should produce non-empty output",
                fixture
            );
            assert!(
                output.function_count > 0,
                "Fixture {} should detect functions",
                fixture
            );
        }
    }
}
