//! Function Boundary Detection
//!
//! Detects function boundaries in PVM binaries using:
//! 1. CFG disconnected component analysis — subgraphs with no edges between them
//! 2. Stack frame prologue detection — `sp = sp - N` patterns at block entries
//! 3. Return detection — `JumpInd` to a register loaded from the stack (epilogue)
//!
//! Each detected function is represented as a set of basic block PCs with an
//! entry point, enabling independent analysis (dataflow, lifting, structuring).

use crate::cfg::ControlFlowGraph;
use crate::instruction::InstructionShape;
use std::collections::{HashMap, HashSet, VecDeque};

/// A detected function within the PVM binary.
#[derive(Debug, Clone)]
pub struct Function {
    /// Entry block PC (where execution of this function begins).
    pub entry_pc: usize,
    /// Set of basic block start PCs belonging to this function.
    pub block_pcs: HashSet<usize>,
    /// Auto-generated name for display.
    pub name: String,
}

/// Detect function boundaries and return a list of functions.
///
/// The detection uses a two-phase approach:
/// 1. Forward reachability from the entry point to find the "main" function.
/// 2. Remaining blocks are grouped into separate functions via connected components.
/// 3. Within each component, stack frame prologues are used to split further.
pub fn detect_functions(cfg: &ControlFlowGraph) -> Vec<Function> {
    if cfg.blocks.is_empty() {
        return vec![];
    }

    // Phase 1: Find connected components (treating edges as undirected).
    let components = find_connected_components(cfg);

    // Phase 2: For each component, attempt to split at stack frame prologues.
    let mut functions = Vec::new();
    let mut func_idx = 0;

    for component in components {
        let sub_functions = split_at_prologues(cfg, &component);

        for sub_fn in sub_functions {
            let name = if sub_fn.entry_pc == cfg.entry_pc {
                "main".to_string()
            } else {
                format!("func_{}", func_idx)
            };
            func_idx += 1;
            functions.push(Function {
                entry_pc: sub_fn.entry_pc,
                block_pcs: sub_fn.block_pcs,
                name,
            });
        }
    }

    // Sort by entry PC for deterministic output.
    functions.sort_by_key(|f| f.entry_pc);

    // Re-number non-main functions for clean naming.
    let mut idx = 0;
    for f in &mut functions {
        if f.name != "main" {
            f.name = format!("func_{}", idx);
            idx += 1;
        }
    }

    functions
}

/// A raw component: entry + block set, before naming.
struct RawFunction {
    entry_pc: usize,
    block_pcs: HashSet<usize>,
}

/// Find connected components in the CFG (treating successor/predecessor edges as undirected).
fn find_connected_components(cfg: &ControlFlowGraph) -> Vec<HashSet<usize>> {
    let mut visited: HashSet<usize> = HashSet::new();
    let mut components = Vec::new();

    // Process entry component first to ensure it's component[0].
    if cfg.blocks.contains_key(&cfg.entry_pc) {
        let component = bfs_component(cfg, cfg.entry_pc, &mut visited);
        components.push(component);
    }

    // Find remaining components from unvisited blocks.
    let mut remaining: Vec<usize> = cfg
        .blocks
        .keys()
        .copied()
        .filter(|pc| !visited.contains(pc))
        .collect();
    remaining.sort();

    for &start in &remaining {
        if visited.contains(&start) {
            continue;
        }
        let component = bfs_component(cfg, start, &mut visited);
        components.push(component);
    }

    components
}

/// BFS from a start block, following both successors and predecessors (undirected).
fn bfs_component(
    cfg: &ControlFlowGraph,
    start: usize,
    visited: &mut HashSet<usize>,
) -> HashSet<usize> {
    let mut component = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);

    while let Some(pc) = queue.pop_front() {
        if !visited.insert(pc) {
            continue;
        }
        component.insert(pc);

        if let Some(block) = cfg.blocks.get(&pc) {
            for &succ in &block.successors {
                if !visited.contains(&succ) {
                    queue.push_back(succ);
                }
            }
            for &pred in &block.predecessors {
                if !visited.contains(&pred) {
                    queue.push_back(pred);
                }
            }
        }
    }

    component
}

/// Within a connected component, attempt to split at stack frame prologues.
///
/// A stack frame prologue is detected when a block:
/// 1. Starts with `sp = sp + negative_value` (stack allocation via AddImm on SP register)
/// 2. Has predecessors from outside the natural forward-reachable set
///
/// If no prologues are found, the entire component is returned as one function.
fn split_at_prologues(cfg: &ControlFlowGraph, component: &HashSet<usize>) -> Vec<RawFunction> {
    if component.len() <= 1 {
        let entry = *component.iter().min().unwrap();
        return vec![RawFunction {
            entry_pc: entry,
            block_pcs: component.clone(),
        }];
    }

    // Find potential function entries: blocks with prologue patterns.
    let mut prologue_entries: Vec<usize> = Vec::new();
    let component_entry = find_component_entry(cfg, component);

    for &block_pc in component {
        if block_pc == component_entry {
            continue; // The main entry is always a function start, handled separately.
        }
        if has_stack_prologue(cfg, block_pc) && is_call_target(cfg, block_pc, component) {
            prologue_entries.push(block_pc);
        }
    }

    if prologue_entries.is_empty() {
        // No sub-functions found; return the whole component as one function.
        return vec![RawFunction {
            entry_pc: component_entry,
            block_pcs: component.clone(),
        }];
    }

    // Build sub-functions by forward reachability from each entry.
    // Process entries in reverse order so that called functions are claimed first,
    // then the caller gets the remaining blocks.
    prologue_entries.sort();
    let all_entries: Vec<usize> = std::iter::once(component_entry)
        .chain(prologue_entries.iter().copied())
        .collect();

    // Assign blocks to the function whose entry they are forward-reachable from.
    // When a block is reachable from multiple entries, assign it to the nearest
    // (smallest distance) entry via BFS.
    let assignments = assign_blocks_to_entries(cfg, component, &all_entries);

    let mut functions: Vec<RawFunction> = Vec::new();
    for &entry in &all_entries {
        let block_pcs: HashSet<usize> = assignments
            .iter()
            .filter(|&(_, &e)| e == entry)
            .map(|(&pc, _)| pc)
            .collect();
        if !block_pcs.is_empty() {
            functions.push(RawFunction {
                entry_pc: entry,
                block_pcs,
            });
        }
    }

    functions
}

/// Find the "entry" of a component — the block with the smallest PC, or the one
/// that has no predecessors within the component.
fn find_component_entry(cfg: &ControlFlowGraph, component: &HashSet<usize>) -> usize {
    // Prefer blocks with no predecessors within the component.
    for &pc in component {
        if let Some(block) = cfg.blocks.get(&pc) {
            let internal_preds: Vec<usize> = block
                .predecessors
                .iter()
                .copied()
                .filter(|p| component.contains(p))
                .collect();
            if internal_preds.is_empty() {
                return pc;
            }
        }
    }
    // Fallback: smallest PC.
    *component.iter().min().unwrap()
}

/// Check if a block starts with a stack frame prologue pattern.
///
/// Looks for: `AddImm{32,64} { dst: SP, src: SP, value: negative }` as the first
/// non-eliminated instruction, where SP is register 2 (PVM convention).
fn has_stack_prologue(cfg: &ControlFlowGraph, block_pc: usize) -> bool {
    const SP: u8 = 2;
    let block = match cfg.blocks.get(&block_pc) {
        Some(b) => b,
        None => return false,
    };

    let (_, first_instr) = match block.instructions.first() {
        Some(pair) => pair,
        None => return false,
    };
    match InstructionShape::classify(first_instr) {
        // SP adjustment: sp = sp + (-N)
        InstructionShape::BinImm {
            dst, src, value, ..
        } if dst == SP && src == SP && value < 0 => true,
        // Store of return address to stack (common prologue pattern).
        InstructionShape::Store { base, .. } if base == SP => true,
        _ => false,
    }
}

/// Check if a block looks like a call target: it is jumped to directly (not just
/// fallen through to) from a predecessor that is likely a call site.
///
/// A call site pattern is: a block that saves a return address to a register
/// and then jumps to the target.
fn is_call_target(cfg: &ControlFlowGraph, block_pc: usize, component: &HashSet<usize>) -> bool {
    let block = match cfg.blocks.get(&block_pc) {
        Some(b) => b,
        None => return false,
    };

    // A function entry should be jumped to (not just fallen through).
    // Check if any predecessor has a Jump instruction targeting this block.
    for &pred_pc in &block.predecessors {
        if !component.contains(&pred_pc) {
            continue;
        }
        if let Some(pred_block) = cfg.blocks.get(&pred_pc)
            && let Some((_, last_instr)) = pred_block.instructions.last()
        {
            let shape = InstructionShape::classify(last_instr);
            // Direct jump to this block = likely a call.
            if matches!(shape, InstructionShape::Jump { .. }) {
                return true;
            }
        }
    }
    false
}

/// Assign each block in the component to the nearest function entry via BFS distance.
fn assign_blocks_to_entries(
    cfg: &ControlFlowGraph,
    component: &HashSet<usize>,
    entries: &[usize],
) -> HashMap<usize, usize> {
    let mut assignments: HashMap<usize, usize> = HashMap::new();
    let mut distances: HashMap<usize, usize> = HashMap::new();

    for &entry in entries {
        let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
        queue.push_back((entry, 0));

        while let Some((pc, dist)) = queue.pop_front() {
            if !component.contains(&pc) {
                continue;
            }
            // Only assign if this entry is closer (or equal distance but smaller entry PC).
            let dominated = match distances.get(&pc) {
                None => true,
                Some(&prev_dist) => {
                    dist < prev_dist
                        || (dist == prev_dist
                            && entry < *assignments.get(&pc).unwrap_or(&usize::MAX))
                }
            };
            if !dominated {
                continue;
            }
            distances.insert(pc, dist);
            assignments.insert(pc, entry);

            if let Some(block) = cfg.blocks.get(&pc) {
                for &succ in &block.successors {
                    if component.contains(&succ) {
                        let new_dist = dist + 1;
                        let dominated_succ = match distances.get(&succ) {
                            None => true,
                            Some(&prev) => new_dist < prev,
                        };
                        if dominated_succ {
                            queue.push_back((succ, new_dist));
                        }
                    }
                }
            }
        }
    }

    assignments
}

/// Build a sub-CFG containing only the blocks belonging to a function.
/// Edges to blocks outside the function are removed.
pub fn build_function_cfg(cfg: &ControlFlowGraph, function: &Function) -> ControlFlowGraph {
    let mut sub_cfg = ControlFlowGraph::new(function.entry_pc);

    for &block_pc in &function.block_pcs {
        if let Some(block) = cfg.blocks.get(&block_pc) {
            let mut sub_block = block.clone();
            // Filter edges to only include blocks within this function.
            sub_block
                .successors
                .retain(|s| function.block_pcs.contains(s));
            sub_block
                .predecessors
                .retain(|p| function.block_pcs.contains(p));
            sub_cfg.add_block(sub_block);
        }
    }

    sub_cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_test_cfg;
    use wasm_pvm::pvm::Instruction;

    #[test]
    fn test_single_function() {
        // All blocks connected: one function.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::LoadImm { reg: 0, value: 1 })],
                    vec![10],
                ),
                (10, vec![(10, Instruction::Trap)], vec![]),
            ],
        );

        let functions = detect_functions(&cfg);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].entry_pc, 0);
        assert_eq!(functions[0].name, "main");
        assert_eq!(functions[0].block_pcs.len(), 2);
    }

    #[test]
    fn test_disconnected_components() {
        // Two disconnected components: blocks {0, 10} and {100, 110}.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::LoadImm { reg: 0, value: 1 })],
                    vec![10],
                ),
                (10, vec![(10, Instruction::Trap)], vec![]),
                (
                    100,
                    vec![(100, Instruction::LoadImm { reg: 1, value: 2 })],
                    vec![110],
                ),
                (110, vec![(110, Instruction::Trap)], vec![]),
            ],
        );

        let functions = detect_functions(&cfg);
        assert_eq!(functions.len(), 2, "Should detect 2 disconnected functions");

        let main_fn = functions.iter().find(|f| f.entry_pc == 0).unwrap();
        assert_eq!(main_fn.name, "main");
        assert!(main_fn.block_pcs.contains(&0));
        assert!(main_fn.block_pcs.contains(&10));

        let other_fn = functions.iter().find(|f| f.entry_pc == 100).unwrap();
        assert!(other_fn.name.starts_with("func_"));
        assert!(other_fn.block_pcs.contains(&100));
        assert!(other_fn.block_pcs.contains(&110));
    }

    #[test]
    fn test_empty_cfg() {
        let cfg = ControlFlowGraph::new(0);
        let functions = detect_functions(&cfg);
        assert!(functions.is_empty());
    }

    #[test]
    fn test_build_function_cfg_filters_edges() {
        // Function with blocks {0, 10}, block 10 has a successor to block 100 (outside).
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::LoadImm { reg: 0, value: 1 })],
                    vec![10],
                ),
                (10, vec![(10, Instruction::Jump { offset: 90 })], vec![100]),
                (100, vec![(100, Instruction::Trap)], vec![]),
            ],
        );

        let function = Function {
            entry_pc: 0,
            name: "test".to_string(),
            block_pcs: [0, 10].into_iter().collect(),
        };

        let sub_cfg = build_function_cfg(&cfg, &function);
        assert_eq!(sub_cfg.blocks.len(), 2);
        assert_eq!(sub_cfg.entry_pc, 0);

        // Block 10's successor to 100 should be filtered out.
        let block_10 = sub_cfg.blocks.get(&10).unwrap();
        assert!(
            block_10.successors.is_empty(),
            "Successors outside function should be filtered"
        );
    }

    #[test]
    fn test_prologue_detection() {
        // Block at PC 50 starts with sp = sp + (-16) => prologue.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 1 }),
                        (4, Instruction::Jump { offset: 46 }),
                    ],
                    vec![50],
                ),
                (
                    50,
                    vec![
                        (
                            50,
                            Instruction::AddImm64 {
                                dst: 2,
                                src: 2,
                                value: -16,
                            },
                        ),
                        (54, Instruction::Trap),
                    ],
                    vec![],
                ),
            ],
        );

        assert!(has_stack_prologue(&cfg, 50));
        assert!(!has_stack_prologue(&cfg, 0));
    }

    #[test]
    fn test_three_disconnected_functions() {
        let cfg = build_test_cfg(
            0,
            vec![
                (0, vec![(0, Instruction::Trap)], vec![]),
                (50, vec![(50, Instruction::Trap)], vec![]),
                (100, vec![(100, Instruction::Trap)], vec![]),
            ],
        );

        let functions = detect_functions(&cfg);
        assert_eq!(functions.len(), 3);

        // Should be sorted by entry PC.
        assert_eq!(functions[0].entry_pc, 0);
        assert_eq!(functions[1].entry_pc, 50);
        assert_eq!(functions[2].entry_pc, 100);
    }

    /// Integration test: verify that per-function sub-CFGs can be analyzed
    /// through the full pipeline (dataflow + lifting + structuring).
    #[test]
    fn test_per_function_pipeline() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::decoder::DecodedProgram;
        use crate::lifting::LiftedProgram;
        use crate::structuring::StructuralAnalysis;

        // Two disconnected functions: {0,10} and {100,110}.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 42 }),
                        (
                            4,
                            Instruction::AddImm32 {
                                dst: 1,
                                src: 0,
                                value: 1,
                            },
                        ),
                    ],
                    vec![10],
                ),
                (10, vec![(10, Instruction::Trap)], vec![]),
                (
                    100,
                    vec![(100, Instruction::LoadImm { reg: 3, value: 7 })],
                    vec![110],
                ),
                (110, vec![(110, Instruction::Trap)], vec![]),
            ],
        );

        let functions = detect_functions(&cfg);
        assert_eq!(functions.len(), 2);

        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![],
            code_len: 0,
        };

        // Each function should analyze without panic.
        for func in &functions {
            let func_cfg = build_function_cfg(&cfg, func);
            assert_eq!(func_cfg.entry_pc, func.entry_pc);
            assert_eq!(func_cfg.blocks.len(), func.block_pcs.len());

            let dataflow = DataFlowAnalysis::analyze(&func_cfg);
            let mut lifted = LiftedProgram::analyze(&func_cfg, &dataflow);
            let structural = StructuralAnalysis::analyze(&func_cfg, &program);
            let pseudo = structural.pseudo_code(&func_cfg, Some(&mut lifted), None);
            assert!(!pseudo.is_empty(), "Pseudo-code should not be empty");
        }
    }
}
