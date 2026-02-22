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
use crate::decoder::DecodedProgram;
use crate::instruction::InstructionShape;
use std::collections::{HashMap, HashSet, VecDeque};
use wasm_pvm::pvm::Instruction;

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

/// Find the "entry" of a component — the block with no predecessors within the
/// component (choosing the smallest PC if multiple exist), or the smallest PC as fallback.
fn find_component_entry(cfg: &ControlFlowGraph, component: &HashSet<usize>) -> usize {
    // Collect all blocks with no internal predecessors.
    let mut no_pred_entries: Vec<usize> = Vec::new();
    for &pc in component {
        if let Some(block) = cfg.blocks.get(&pc) {
            let has_internal_pred = block.predecessors.iter().any(|p| component.contains(p));
            if !has_internal_pred {
                no_pred_entries.push(pc);
            }
        }
    }
    if !no_pred_entries.is_empty() {
        // Deterministic: pick the smallest PC among candidates.
        return *no_pred_entries.iter().min().unwrap();
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

/// A call site: a block in one function that has an edge to another function's entry.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// PC of the block containing the call (the last instruction is the jump/branch).
    pub caller_block_pc: usize,
    /// Entry PC of the called function.
    pub callee_entry_pc: usize,
    /// Name of the called function.
    pub callee_name: String,
}

/// Build a call graph: find all cross-function edges and map them to call sites.
/// Returns a map from caller function entry PC → list of call sites.
///
/// Detection method:
/// 1. Direct CFG edges from one function to another function's entry
pub fn build_call_graph(
    cfg: &ControlFlowGraph,
    functions: &[Function],
    _program: &DecodedProgram,
) -> HashMap<usize, Vec<CallSite>> {
    // Build a lookup: block_pc → function entry_pc
    let mut block_to_func: HashMap<usize, usize> = HashMap::new();
    for func in functions {
        for &block_pc in &func.block_pcs {
            block_to_func.insert(block_pc, func.entry_pc);
        }
    }

    // Build a lookup: function entry_pc → function name
    let func_names: HashMap<usize, String> = functions
        .iter()
        .map(|f| (f.entry_pc, f.name.clone()))
        .collect();

    let mut call_graph: HashMap<usize, Vec<CallSite>> = HashMap::new();

    for func in functions {
        for &block_pc in &func.block_pcs {
            if let Some(block) = cfg.blocks.get(&block_pc) {
                // Method 1: Direct CFG edges to other function entries
                for &succ in &block.successors {
                    if let Some(&succ_func_entry) = block_to_func.get(&succ)
                        && succ_func_entry != func.entry_pc
                        && succ == succ_func_entry
                    {
                        let callee_name = func_names
                            .get(&succ_func_entry)
                            .cloned()
                            .unwrap_or_else(|| format!("func_at_{:#06x}", succ_func_entry));
                        call_graph.entry(func.entry_pc).or_default().push(CallSite {
                            caller_block_pc: block_pc,
                            callee_entry_pc: succ_func_entry,
                            callee_name,
                        });
                    }
                }
            }
        }
    }

    call_graph
}

/// A detected direct call pattern: `LoadImm64 r0, N` followed by `Jump target`.
///
/// In the PVM calling convention, the caller sets r0 to the return address
/// (encoded as `(jump_table_index + 1) * 2`) and jumps to the callee.
/// The callee eventually returns via `JumpInd r0`, which goes to
/// `jump_table[r0 / 2 - 1]`.
#[derive(Debug, Clone)]
pub struct DirectCallPattern {
    /// PC of the block containing the call pattern.
    pub caller_block_pc: usize,
    /// PC of the LoadImm64 instruction (to mark as eliminated).
    pub load_imm_pc: usize,
    /// PC of the Jump instruction performing the call.
    pub jump_pc: usize,
    /// PC of the Jump target (callee entry or stack guard).
    pub jump_target_pc: usize,
    /// PC where execution continues after the callee returns.
    pub return_pc: usize,
    /// Resolved callee function name.
    pub callee_name: String,
}

/// PVM jump table alignment factor: addresses are encoded as `(index + 1) * 2`.
const JUMP_ALIGNMENT_FACTOR: u64 = 2;

/// Detect direct call patterns (`LoadImm64 r0, N` + `Jump`) in the CFG.
///
/// Returns a list of detected call patterns. Each pattern identifies:
/// - The call site (block and instruction PCs)
/// - The callee (via jump target's containing function, with trampoline fallback)
/// - PCs to eliminate from output (the LoadImm64 setting return address)
pub fn detect_direct_call_patterns(
    cfg: &ControlFlowGraph,
    functions: &[Function],
    program: &DecodedProgram,
) -> Vec<DirectCallPattern> {
    let func_names: HashMap<usize, String> = functions
        .iter()
        .map(|f| (f.entry_pc, f.name.clone()))
        .collect();

    // Build block_pc → function entry lookup
    let block_to_func: HashMap<usize, usize> = functions
        .iter()
        .flat_map(|f| f.block_pcs.iter().map(move |&bp| (bp, f.entry_pc)))
        .collect();
    let func_entries: HashSet<usize> = functions.iter().map(|f| f.entry_pc).collect();

    let mut patterns = Vec::new();

    for block in cfg.blocks.values() {
        let instrs = &block.instructions;
        let len = instrs.len();
        if len < 2 {
            continue;
        }

        // Look for LoadImm64 { reg: 0, value: N } followed (possibly with Fallthrough) by Jump
        for i in 0..len - 1 {
            let (load_pc, load_instr) = &instrs[i];

            if let Instruction::LoadImm64 { reg: 0, value } = load_instr {
                // Find the next non-Fallthrough instruction
                let mut jump_idx = i + 1;
                while jump_idx < len && matches!(instrs[jump_idx].1, Instruction::Fallthrough) {
                    jump_idx += 1;
                }
                if jump_idx >= len {
                    continue;
                }

                let (jump_pc, jump_instr) = &instrs[jump_idx];

                if let Instruction::Jump { offset } = jump_instr {
                    let encoded_addr = *value;

                    // Validate: must be even, non-zero, and within jump table bounds
                    if encoded_addr == 0 || !encoded_addr.is_multiple_of(JUMP_ALIGNMENT_FACTOR) {
                        continue;
                    }

                    let table_index = (encoded_addr / JUMP_ALIGNMENT_FACTOR - 1) as usize;
                    if table_index >= program.jump_table.len() {
                        continue;
                    }

                    let jump_target =
                        crate::cfg::ControlFlowGraph::compute_jump_target(*jump_pc, *offset);
                    let return_pc = program.jump_table[table_index] as usize;

                    let Some(&caller_func_entry) = block_to_func.get(&block.start_pc) else {
                        continue;
                    };
                    let Some(&jump_target_func_entry) = block_to_func.get(&jump_target) else {
                        // Jump target isn't in any known function.
                        continue;
                    };
                    let callee_func_entry = if caller_func_entry == jump_target_func_entry {
                        // Trampoline fallback: some binaries jump to shared stack-guard blocks
                        // in the current function before transferring to the real callee entry.
                        // Only treat this as a call when return_pc is itself another function entry.
                        if func_entries.contains(&return_pc) && return_pc != caller_func_entry {
                            return_pc
                        } else {
                            continue;
                        }
                    } else {
                        jump_target_func_entry
                    };

                    // `return_pc` is continuation metadata for after the callee returns.
                    // In trampoline fallback cases above, it can also identify
                    // the callee entry when jump_target remains in the caller.
                    let callee_name = func_names
                        .get(&callee_func_entry)
                        .cloned()
                        .unwrap_or_else(|| format!("func_at_{:#06x}", callee_func_entry));

                    patterns.push(DirectCallPattern {
                        caller_block_pc: block.start_pc,
                        load_imm_pc: *load_pc,
                        jump_pc: *jump_pc,
                        jump_target_pc: jump_target,
                        return_pc,
                        callee_name,
                    });
                }
            }
        }
    }

    patterns
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

/// Detected epilogue type for a block.
#[derive(Debug, Clone)]
pub enum EpilogueKind {
    /// Function return: restore callee-saved registers, restore r0, sp += N, JumpInd r0.
    /// Contains the PCs of all epilogue instructions to eliminate.
    Return { eliminated_pcs: Vec<usize> },
    /// Program halt: LoadImm reg = -65536, JumpInd reg.
    /// Contains the PCs of the halt instructions to eliminate.
    Halt { eliminated_pcs: Vec<usize> },
}

/// Detect epilogue patterns in a function's blocks.
/// Returns a map from block_pc → EpilogueKind for blocks that contain epilogues.
pub fn detect_epilogues(cfg: &ControlFlowGraph) -> HashMap<usize, EpilogueKind> {
    let mut epilogues = HashMap::new();

    for (&block_pc, block) in &cfg.blocks {
        if block.instructions.is_empty() {
            continue;
        }

        // Check for halt pattern: LoadImm reg = -65536 + JumpInd reg
        if block.instructions.len() >= 2 {
            let last_idx = block.instructions.len() - 1;
            let (jump_pc, jump_instr) = &block.instructions[last_idx];
            let (load_pc, load_instr) = &block.instructions[last_idx - 1];

            if let Instruction::JumpInd { reg: jump_reg, .. } = jump_instr
                && let Instruction::LoadImm {
                    reg: load_reg,
                    value: -65536,
                } = load_instr
                && jump_reg == load_reg
            {
                epilogues.insert(
                    block_pc,
                    EpilogueKind::Halt {
                        eliminated_pcs: vec![*load_pc, *jump_pc],
                    },
                );
                continue;
            }
        }

        // Check for return pattern: restore registers, restore r0, sp += N, JumpInd r0
        // Working backwards from the end of the block:
        //   JumpInd { reg: 0, offset: 0 }
        //   AddImm64 { dst: 1, src: 1, value: +N }    (sp += frame_size)
        //   LoadIndU64 { dst: 0, base: 1, offset: 0 }  (restore r0)
        //   LoadIndU64 { dst: 12, base: 1, ... }        (restore r12, optional)
        //   LoadIndU64 { dst: 11, base: 1, ... }        (restore r11, optional)
        //   LoadIndU64 { dst: 10, base: 1, ... }        (restore r10, optional)
        //   LoadIndU64 { dst: 9, base: 1, ... }         (restore r9, optional)
        let instrs = &block.instructions;
        let len = instrs.len();
        if len < 3 {
            continue;
        }

        let (jump_pc, jump_instr) = &instrs[len - 1];
        if !matches!(jump_instr, Instruction::JumpInd { reg: 0, offset: 0 }) {
            continue;
        }

        let (sp_pc, sp_instr) = &instrs[len - 2];
        let is_sp_restore =
            matches!(sp_instr, Instruction::AddImm64 { dst: 1, src: 1, value } if *value > 0);
        if !is_sp_restore {
            continue;
        }

        let (r0_pc, r0_instr) = &instrs[len - 3];
        let is_r0_restore = matches!(
            r0_instr,
            Instruction::LoadIndU64 {
                dst: 0,
                base: 1,
                ..
            }
        );
        if !is_r0_restore {
            continue;
        }

        let mut eliminated_pcs = vec![*r0_pc, *sp_pc, *jump_pc];

        // Scan backwards for callee-saved register restores (r9-r12)
        let callee_saved = [9u8, 10, 11, 12];
        let mut scan_idx = len.saturating_sub(4); // start before r0 restore
        while scan_idx > 0 {
            let idx = scan_idx;
            scan_idx -= 1;

            let (pc, instr) = &instrs[idx];
            if let Instruction::LoadIndU64 { dst, base: 1, .. } = instr
                && callee_saved.contains(dst)
            {
                eliminated_pcs.push(*pc);
            } else {
                break;
            }
        }

        epilogues.insert(block_pc, EpilogueKind::Return { eliminated_pcs });
    }

    epilogues
}

/// Detect prologue patterns in a function's entry block.
/// Returns a list of PCs to eliminate (stack guard, frame allocation, register saves).
///
/// wasm-pvm prologue pattern:
///   LoadImm64 { reg: 2, value: <stack_guard> }    // stack guard constant
///   AddImm64 { dst: 3, src: 1, value: -N }        // compute stack limit
///   BranchGeU { reg1: 2, reg2: 3, ... }            // guard check
///   Trap                                            // (in a separate block)
///   AddImm64 { dst: 1, src: 1, value: -N }        // frame allocation
///   StoreIndU64 { base: 1, src: 0, offset: 0 }    // save r0
///   StoreIndU64 { base: 1, src: 9, offset: ... }  // save r9
///   StoreIndU64 { base: 1, src: 10, offset: ... } // save r10
///   StoreIndU64 { base: 1, src: 11, offset: ... } // save r11
///   StoreIndU64 { base: 1, src: 12, offset: ... } // save r12
pub fn detect_prologue(cfg: &ControlFlowGraph, entry_pc: usize) -> Vec<usize> {
    let mut eliminated = Vec::new();

    // Collect all blocks reachable from entry in order
    let entry_block = match cfg.blocks.get(&entry_pc) {
        Some(b) => b,
        None => return eliminated,
    };

    // Phase 1: Check for stack guard pattern in the entry block
    let instrs = &entry_block.instructions;
    let mut idx = 0;

    // Skip initial Jump (dispatch to main) or Fallthrough
    while idx < instrs.len() {
        let (_, instr) = &instrs[idx];
        if matches!(instr, Instruction::Fallthrough) {
            idx += 1;
        } else {
            break;
        }
    }

    // Look for: LoadImm64 (stack guard value) + AddImm64 (stack limit) + BranchGeU (guard check)
    if idx + 2 < instrs.len() {
        let (pc0, instr0) = &instrs[idx];
        let (pc1, instr1) = &instrs[idx + 1];
        let (pc2, instr2) = &instrs[idx + 2];

        let is_stack_guard = matches!(instr0, Instruction::LoadImm64 { reg: 2, .. })
            && matches!(instr1, Instruction::AddImm64 { dst: 3, src: 1, value } if *value < 0)
            && matches!(
                instr2,
                Instruction::BranchGeU {
                    reg1: 2,
                    reg2: 3,
                    ..
                }
            );

        if is_stack_guard {
            eliminated.push(*pc0);
            eliminated.push(*pc1);
            eliminated.push(*pc2);
            // The Trap block (reached by the guard) will be emitted naturally
        }
    }

    // Phase 2: Find the frame allocation and register saves
    // These might be in the entry block (after the guard) or in a successor block
    let blocks_to_check: Vec<usize> = {
        let mut blocks = vec![entry_pc];
        blocks.extend(entry_block.successors.iter());
        blocks
    };

    for &block_pc in &blocks_to_check {
        if let Some(block) = cfg.blocks.get(&block_pc) {
            for (pc, instr) in &block.instructions {
                match instr {
                    // Frame allocation: sp -= N
                    Instruction::AddImm64 {
                        dst: 1,
                        src: 1,
                        value,
                    } if *value < 0 => {
                        eliminated.push(*pc);
                    }
                    // Save return address: [sp+0] = r0
                    Instruction::StoreIndU64 {
                        base: 1,
                        src: 0,
                        offset: 0,
                    } => {
                        eliminated.push(*pc);
                    }
                    // Save callee-saved registers: [sp+N] = r9/r10/r11/r12
                    Instruction::StoreIndU64 { base: 1, src, .. }
                        if [9u8, 10, 11, 12].contains(src) =>
                    {
                        eliminated.push(*pc);
                    }
                    _ => {}
                }
            }
        }
    }

    eliminated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_test_cfg;
    use crate::decoder::DecodedProgram;
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
            memory_base: None,
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

    #[test]
    fn test_build_call_graph() {
        // Build a CFG where block 10 (in func_0) has a successor edge to 0x100
        // (entry of func_1). We manually specify the function boundaries to
        // simulate what detect_functions + split_at_prologues would produce.
        let cfg = build_test_cfg(
            0,
            vec![
                // func_0: block at 0
                (
                    0,
                    vec![(0, Instruction::LoadImm { reg: 0, value: 1 })],
                    vec![10],
                ),
                // func_0: block at 10, has a cross-function edge to 0x100
                (
                    10,
                    vec![(
                        10,
                        Instruction::Jump {
                            offset: 0x100_i32 - 10,
                        },
                    )],
                    vec![0x100],
                ),
                // func_1: entry block at 0x100
                (
                    0x100,
                    vec![(0x100, Instruction::LoadImm { reg: 1, value: 2 })],
                    vec![0x110],
                ),
                // func_1: exit block
                (0x110, vec![(0x110, Instruction::Trap)], vec![]),
            ],
        );

        // Manually define function boundaries (simulating prologue-based split)
        let functions = vec![
            Function {
                entry_pc: 0,
                block_pcs: [0, 10].iter().copied().collect(),
                name: "main".to_string(),
            },
            Function {
                entry_pc: 0x100,
                block_pcs: [0x100, 0x110].iter().copied().collect(),
                name: "func_0".to_string(),
            },
        ];

        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![],
            memory_base: None,
            code_len: 0,
        };
        let call_graph = build_call_graph(&cfg, &functions, &program);

        // main should have a call to func_0
        let calls = call_graph.get(&0usize);
        assert!(calls.is_some(), "main should have call sites");

        let calls = calls.unwrap();
        assert_eq!(calls.len(), 1, "main should call exactly one function");
        assert_eq!(calls[0].callee_entry_pc, 0x100);
        assert_eq!(calls[0].caller_block_pc, 10);
        assert_eq!(calls[0].callee_name, "func_0");

        // func_0 should have no outgoing calls
        assert!(
            call_graph.get(&0x100usize).is_none(),
            "func_0 should have no call sites"
        );
    }

    #[test]
    fn test_detect_epilogue_return_pattern() {
        // Block with: restore r9, restore r0, sp += 40, JumpInd r0
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 5, value: 42 }), // some instruction
                    (
                        4,
                        Instruction::LoadIndU64 {
                            dst: 9,
                            base: 1,
                            offset: 8,
                        },
                    ), // restore r9
                    (
                        7,
                        Instruction::LoadIndU64 {
                            dst: 0,
                            base: 1,
                            offset: 0,
                        },
                    ), // restore r0
                    (
                        10,
                        Instruction::AddImm64 {
                            dst: 1,
                            src: 1,
                            value: 40,
                        },
                    ), // sp += 40
                    (13, Instruction::JumpInd { reg: 0, offset: 0 }), // return
                ],
                vec![],
            )],
        );

        let epilogues = detect_epilogues(&cfg);
        assert!(
            epilogues.contains_key(&0),
            "Block 0 should be a return epilogue"
        );
        assert!(
            matches!(epilogues[&0], EpilogueKind::Return { .. }),
            "Should be Return kind"
        );
        if let EpilogueKind::Return { ref eliminated_pcs } = epilogues[&0] {
            // Should eliminate: restore r0, sp +=, JumpInd, and r9 restore
            assert!(
                eliminated_pcs.contains(&7),
                "r0 restore should be eliminated"
            );
            assert!(
                eliminated_pcs.contains(&10),
                "sp adjust should be eliminated"
            );
            assert!(eliminated_pcs.contains(&13), "JumpInd should be eliminated");
            assert!(
                eliminated_pcs.contains(&4),
                "r9 restore should be eliminated"
            );
            assert!(
                !eliminated_pcs.contains(&0),
                "non-epilogue instruction should not be eliminated"
            );
        }
    }

    #[test]
    fn test_detect_epilogue_halt_pattern() {
        // Block with: LoadImm r2 = -65536, JumpInd r2
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 5, value: 42 }),
                    (
                        4,
                        Instruction::LoadImm {
                            reg: 2,
                            value: -65536,
                        },
                    ),
                    (8, Instruction::JumpInd { reg: 2, offset: 0 }),
                ],
                vec![],
            )],
        );

        let epilogues = detect_epilogues(&cfg);
        assert!(
            epilogues.contains_key(&0),
            "Block 0 should be a halt epilogue"
        );
        assert!(
            matches!(epilogues[&0], EpilogueKind::Halt { .. }),
            "Should be Halt kind"
        );
        if let EpilogueKind::Halt { ref eliminated_pcs } = epilogues[&0] {
            assert!(eliminated_pcs.contains(&4), "LoadImm should be eliminated");
            assert!(eliminated_pcs.contains(&8), "JumpInd should be eliminated");
        }
    }

    #[test]
    fn test_detect_epilogue_no_match() {
        // Block with JumpInd but not matching return or halt pattern
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 5, value: 42 }),
                    (4, Instruction::JumpInd { reg: 5, offset: 0 }),
                ],
                vec![],
            )],
        );

        let epilogues = detect_epilogues(&cfg);
        assert!(epilogues.is_empty(), "Should not detect epilogue");
    }

    #[test]
    fn test_detect_prologue_stack_guard() {
        // Entry block with stack guard: LoadImm64 r2, AddImm64 r3 = r1 - N, BranchGeU r2 r3
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (
                            0,
                            Instruction::LoadImm64 {
                                reg: 2,
                                value: 4277993472,
                            },
                        ),
                        (
                            10,
                            Instruction::AddImm64 {
                                dst: 3,
                                src: 1,
                                value: -40,
                            },
                        ),
                        (
                            14,
                            Instruction::BranchGeU {
                                reg1: 2,
                                reg2: 3,
                                offset: 10,
                            },
                        ),
                    ],
                    vec![20, 24],
                ),
                (20, vec![(20, Instruction::Trap)], vec![]),
                (
                    24,
                    vec![
                        (
                            24,
                            Instruction::AddImm64 {
                                dst: 1,
                                src: 1,
                                value: -40,
                            },
                        ),
                        (
                            28,
                            Instruction::StoreIndU64 {
                                base: 1,
                                src: 0,
                                offset: 0,
                            },
                        ),
                        (
                            31,
                            Instruction::StoreIndU64 {
                                base: 1,
                                src: 9,
                                offset: 8,
                            },
                        ),
                    ],
                    vec![],
                ),
            ],
        );

        let eliminated = detect_prologue(&cfg, 0);
        // Stack guard instructions
        assert!(eliminated.contains(&0), "LoadImm64 should be eliminated");
        assert!(eliminated.contains(&10), "AddImm64 should be eliminated");
        assert!(eliminated.contains(&14), "BranchGeU should be eliminated");
        // Frame allocation and register saves in successor block
        assert!(eliminated.contains(&24), "sp -= 40 should be eliminated");
        assert!(eliminated.contains(&28), "save r0 should be eliminated");
        assert!(eliminated.contains(&31), "save r9 should be eliminated");
    }

    #[test]
    fn test_return_epilogue_excludes_from_call_graph() {
        // Block 0 jumps to block 10 (func_0 entry).
        // Block 20 is a return epilogue (JumpInd r0) — should NOT be a call site.
        let cfg = build_test_cfg(
            0,
            vec![
                (0, vec![(0, Instruction::Jump { offset: 10 })], vec![10]),
                (10, vec![(10, Instruction::Trap)], vec![]),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::LoadIndU64 {
                                dst: 0,
                                base: 1,
                                offset: 0,
                            },
                        ),
                        (
                            23,
                            Instruction::AddImm64 {
                                dst: 1,
                                src: 1,
                                value: 40,
                            },
                        ),
                        (26, Instruction::JumpInd { reg: 0, offset: 0 }),
                    ],
                    vec![],
                ),
            ],
        );

        let functions = vec![
            Function {
                entry_pc: 0,
                block_pcs: [0, 20].iter().copied().collect(),
                name: "main".to_string(),
            },
            Function {
                entry_pc: 10,
                block_pcs: [10].iter().copied().collect(),
                name: "func_0".to_string(),
            },
        ];

        let program = DecodedProgram {
            jump_table: vec![10], // jump_table[0] = func_0 entry
            instructions: vec![],
            memory_base: None,
            code_len: 0,
        };
        let call_graph = build_call_graph(&cfg, &functions, &program);

        // main should call func_0 via direct Jump, but block 20 (epilogue) should NOT
        // generate an indirect call via jump table
        let main_calls = call_graph.get(&0usize);
        if let Some(calls) = main_calls {
            // Should only have the direct call from block 0, not from block 20
            assert!(
                !calls.iter().any(|c| c.caller_block_pc == 20),
                "Return epilogue block should not be a call site"
            );
        }
    }

    #[test]
    fn test_build_call_graph_does_not_guess_jumpind_targets() {
        // Main has a JumpInd callsite and jump_table points at func_0 entry,
        // but without proof this must not become a concrete call edge.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 5, value: 0x100 }),
                        (4, Instruction::JumpInd { reg: 5, offset: 0 }),
                    ],
                    vec![],
                ),
                (0x100, vec![(0x100, Instruction::Trap)], vec![]),
            ],
        );

        let functions = vec![
            Function {
                entry_pc: 0,
                block_pcs: [0].into_iter().collect(),
                name: "main".to_string(),
            },
            Function {
                entry_pc: 0x100,
                block_pcs: [0x100].into_iter().collect(),
                name: "func_0".to_string(),
            },
        ];

        let program = DecodedProgram {
            jump_table: vec![0x100],
            instructions: vec![],
            memory_base: None,
            code_len: 0,
        };
        let call_graph = build_call_graph(&cfg, &functions, &program);
        assert!(
            call_graph.get(&0usize).is_none(),
            "JumpInd should not be guessed to all jump-table function entries"
        );
    }

    #[test]
    fn test_detect_direct_call_pattern() {
        // Build a program with:
        // Block 0: LoadImm64 r0, 2 + Jump to block 100 (callee entry)
        // Block 60: caller continuation (this is where jump_table[0] points = return point)
        // Jump table: [60] (so address 2 → index (2/2-1) = 0 → jump_table[0] = 60)
        //
        // Regression: the callee must come from jump_target (100), not return_pc (60).
        let program = DecodedProgram {
            instructions: vec![
                (0, Instruction::LoadImm64 { reg: 0, value: 2 }),
                (10, Instruction::Jump { offset: 90 }),
                (60, Instruction::Trap),
                (100, Instruction::Trap),
            ],
            jump_table: vec![60],
            code_len: 101,
            memory_base: None,
        };

        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm64 { reg: 0, value: 2 }),
                        (10, Instruction::Jump { offset: 90 }),
                    ],
                    vec![100],
                ),
                (60, vec![(60, Instruction::Trap)], vec![]),
                (100, vec![(100, Instruction::Trap)], vec![]),
            ],
        );

        let functions = vec![
            Function {
                entry_pc: 0,
                block_pcs: [0, 60].into_iter().collect(),
                name: "main".to_string(),
            },
            Function {
                entry_pc: 100,
                block_pcs: [100].into_iter().collect(),
                name: "func_1".to_string(),
            },
        ];

        let patterns = detect_direct_call_patterns(&cfg, &functions, &program);
        assert_eq!(patterns.len(), 1, "Should detect one call pattern");
        assert_eq!(patterns[0].caller_block_pc, 0);
        assert_eq!(patterns[0].jump_pc, 10);
        assert_eq!(patterns[0].jump_target_pc, 100);
        assert_eq!(patterns[0].return_pc, 60);
        assert_eq!(patterns[0].callee_name, "func_1");
        assert_eq!(patterns[0].load_imm_pc, 0);
    }

    #[test]
    fn test_detect_direct_call_pattern_uses_return_entry_for_trampoline() {
        // Build a pattern where jump_target stays in the caller function
        // while return_pc points to another function entry.
        // This should still resolve to the return_pc function entry.
        let program = DecodedProgram {
            instructions: vec![
                (0, Instruction::LoadImm64 { reg: 0, value: 2 }),
                (10, Instruction::Jump { offset: 90 }),
                (50, Instruction::Trap),
                (100, Instruction::Trap),
            ],
            jump_table: vec![50],
            code_len: 101,
            memory_base: None,
        };

        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm64 { reg: 0, value: 2 }),
                        (10, Instruction::Jump { offset: 90 }),
                    ],
                    vec![100],
                ),
                (50, vec![(50, Instruction::Trap)], vec![]),
                (100, vec![(100, Instruction::Trap)], vec![]),
            ],
        );

        let functions = vec![
            Function {
                entry_pc: 0,
                block_pcs: [0, 100].into_iter().collect(),
                name: "main".to_string(),
            },
            Function {
                entry_pc: 50,
                block_pcs: [50].into_iter().collect(),
                name: "func_1".to_string(),
            },
        ];

        let patterns = detect_direct_call_patterns(&cfg, &functions, &program);
        assert_eq!(patterns.len(), 1, "Should resolve trampoline call");
        assert_eq!(patterns[0].jump_pc, 10);
        assert_eq!(patterns[0].jump_target_pc, 100);
        assert_eq!(patterns[0].return_pc, 50);
        assert_eq!(patterns[0].callee_name, "func_1");
    }

    #[test]
    fn test_detect_direct_call_pattern_ignores_intra_function_jumps_without_external_entry() {
        let program = DecodedProgram {
            instructions: vec![
                (0, Instruction::LoadImm64 { reg: 0, value: 2 }),
                (10, Instruction::Jump { offset: 90 }),
                (60, Instruction::Trap),
                (100, Instruction::Trap),
            ],
            jump_table: vec![60],
            code_len: 101,
            memory_base: None,
        };

        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm64 { reg: 0, value: 2 }),
                        (10, Instruction::Jump { offset: 90 }),
                    ],
                    vec![100],
                ),
                (60, vec![(60, Instruction::Trap)], vec![]),
                (100, vec![(100, Instruction::Trap)], vec![]),
            ],
        );

        let functions = vec![Function {
            entry_pc: 0,
            block_pcs: [0, 60, 100].into_iter().collect(),
            name: "main".to_string(),
        }];

        let patterns = detect_direct_call_patterns(&cfg, &functions, &program);
        assert!(
            patterns.is_empty(),
            "Intra-function jump targets should not be treated as calls"
        );
    }
}
