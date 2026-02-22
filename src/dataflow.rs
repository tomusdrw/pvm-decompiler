//! Data Flow Analysis for PVM Disassembler
//!
//! This module provides def-use chain analysis to track register definitions
//! and their uses across basic blocks. This is foundational for:
//! - Variable recovery (registers → high-level variables)
//! - Dead code detection
//! - Constant propagation preparation
//! - Understanding data dependencies

use crate::cfg::{BasicBlock, ControlFlowGraph};
use crate::instruction::InstructionShape;
use std::collections::{HashMap, HashSet};
use wasm_pvm::pvm::Instruction;

/// Represents where a register is defined.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Definition {
    pub pc: usize,
    pub reg: u8,
}

/// Represents where a register is used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Use {
    pub pc: usize,
    pub reg: u8,
}

/// Def-Use chain for a single definition: one definition mapped to all its uses.
#[derive(Debug, Clone)]
pub struct DefUseChain {
    pub definition: Definition,
    pub uses: Vec<Use>,
}

/// Result of data flow analysis for the entire program.
#[derive(Debug)]
pub struct DataFlowAnalysis {
    /// All def-use chains in the program, keyed by definition PC.
    pub chains: HashMap<usize, Vec<DefUseChain>>,
    /// Registers defined at each PC.
    pub defs_at_pc: HashMap<usize, Vec<u8>>,
    /// Registers used at each PC.
    pub uses_at_pc: HashMap<usize, Vec<u8>>,
    /// Live-in registers for each basic block (registers needed from predecessors).
    pub live_in: HashMap<usize, HashSet<u8>>,
    /// Live-out registers for each basic block (registers needed by successors).
    pub live_out: HashMap<usize, HashSet<u8>>,
}

impl DataFlowAnalysis {
    /// Perform data flow analysis on a control flow graph.
    pub fn analyze(cfg: &ControlFlowGraph) -> Self {
        let mut analysis = DataFlowAnalysis {
            chains: HashMap::new(),
            defs_at_pc: HashMap::new(),
            uses_at_pc: HashMap::new(),
            live_in: HashMap::new(),
            live_out: HashMap::new(),
        };

        // Step 1: Extract defs and uses for each instruction
        for block in cfg.blocks.values() {
            for (pc, instr) in &block.instructions {
                let (defs, uses) = extract_def_use(instr);
                if !defs.is_empty() {
                    analysis.defs_at_pc.insert(*pc, defs);
                }
                if !uses.is_empty() {
                    analysis.uses_at_pc.insert(*pc, uses);
                }
            }
        }

        // Step 2: Compute live-in and live-out sets using iterative dataflow
        analysis.compute_liveness(cfg);

        // Step 3: Build def-use chains
        analysis.build_chains(cfg);

        analysis
    }

    /// Iterative liveness analysis using standard dataflow equations:
    /// - live_in[B] = use[B] ∪ (live_out[B] - def[B])
    /// - live_out[B] = ∪ live_in[S] for all successors S of B
    ///
    /// Uses a worklist algorithm with reverse postorder for fast convergence.
    /// Register sets are represented as u16 bitmasks for efficiency (PVM has 13 regs).
    fn compute_liveness(&mut self, cfg: &ControlFlowGraph) {
        // Helper: convert HashSet<u8> to bitmask
        fn to_mask(set: &HashSet<u8>) -> u16 {
            set.iter().fold(0u16, |acc, &r| acc | (1 << r))
        }
        // Helper: convert bitmask to HashSet<u8>
        fn to_set(mask: u16) -> HashSet<u8> {
            (0..16).filter(|&r| mask & (1 << r) != 0).collect()
        }

        // Compute use[B] and def[B] for each block as bitmasks
        let mut block_use: HashMap<usize, u16> = HashMap::new();
        let mut block_def: HashMap<usize, u16> = HashMap::new();

        for (block_pc, block) in &cfg.blocks {
            let (uses, defs) = compute_block_use_def(block, &self.defs_at_pc, &self.uses_at_pc);
            block_use.insert(*block_pc, to_mask(&uses));
            block_def.insert(*block_pc, to_mask(&defs));
        }

        // Bitmask-based live_in/live_out for fast computation
        let mut live_in_mask: HashMap<usize, u16> = HashMap::new();
        let mut live_out_mask: HashMap<usize, u16> = HashMap::new();
        for block_pc in cfg.blocks.keys() {
            live_in_mask.insert(*block_pc, 0);
            live_out_mask.insert(*block_pc, 0);
        }

        // Compute reverse postorder
        let rpo = Self::reverse_postorder(cfg);

        // Build predecessor map
        let mut pred_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for (block_pc, block) in &cfg.blocks {
            pred_map.entry(*block_pc).or_default();
            for succ in &block.successors {
                pred_map.entry(*succ).or_default().push(*block_pc);
            }
        }

        // Worklist-based iteration
        let mut in_worklist: HashSet<usize> = HashSet::new();
        let mut worklist: Vec<usize> = rpo.iter().rev().copied().collect();
        for &pc in &worklist {
            in_worklist.insert(pc);
        }

        let max_iterations = cfg.blocks.len() * 15;
        let mut iterations = 0;

        while let Some(block_pc) = worklist.pop() {
            in_worklist.remove(&block_pc);
            iterations += 1;
            if iterations > max_iterations {
                break;
            }

            let block = match cfg.blocks.get(&block_pc) {
                Some(b) => b,
                None => continue,
            };

            // live_out[B] = ∪ live_in[S] for all successors S
            let mut new_live_out: u16 = 0;
            for succ_pc in &block.successors {
                new_live_out |= live_in_mask.get(succ_pc).copied().unwrap_or(0);
            }

            // live_in[B] = use[B] | (live_out[B] & !def[B])
            let use_b = block_use.get(&block_pc).copied().unwrap_or(0);
            let def_b = block_def.get(&block_pc).copied().unwrap_or(0);
            let new_live_in = use_b | (new_live_out & !def_b);

            let old_live_in = live_in_mask.get(&block_pc).copied().unwrap_or(0);
            let old_live_out = live_out_mask.get(&block_pc).copied().unwrap_or(0);

            if new_live_in != old_live_in || new_live_out != old_live_out {
                live_in_mask.insert(block_pc, new_live_in);
                live_out_mask.insert(block_pc, new_live_out);

                if let Some(preds) = pred_map.get(&block_pc) {
                    for pred_pc in preds {
                        if !in_worklist.contains(pred_pc) {
                            in_worklist.insert(*pred_pc);
                            worklist.push(*pred_pc);
                        }
                    }
                }
            }
        }

        // Convert bitmasks back to HashSets for the public API
        for (block_pc, mask) in &live_in_mask {
            self.live_in.insert(*block_pc, to_set(*mask));
        }
        for (block_pc, mask) in &live_out_mask {
            self.live_out.insert(*block_pc, to_set(*mask));
        }
    }

    /// Compute reverse postorder traversal of the CFG (iterative to avoid stack overflow).
    fn reverse_postorder(cfg: &ControlFlowGraph) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut postorder = Vec::new();

        // Iterative DFS using an explicit stack.
        // Stack entries: (pc, next_successor_index). When all successors are
        // processed we push the pc onto postorder.
        let dfs_from = |start: usize, visited: &mut HashSet<usize>, postorder: &mut Vec<usize>| {
            if !visited.insert(start) {
                return;
            }
            let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
            while let Some((pc, idx)) = stack.last_mut() {
                let succs = cfg.blocks.get(pc).map(|b| &b.successors[..]).unwrap_or(&[]);
                if *idx < succs.len() {
                    let succ = succs[*idx];
                    *idx += 1;
                    if visited.insert(succ) {
                        stack.push((succ, 0));
                    }
                } else {
                    let pc = *pc;
                    stack.pop();
                    postorder.push(pc);
                }
            }
        };

        dfs_from(cfg.entry_pc, &mut visited, &mut postorder);

        // Also visit any blocks not reachable from entry (disconnected components)
        let mut all_pcs: Vec<usize> = cfg.blocks.keys().copied().collect();
        all_pcs.sort();
        for pc in all_pcs {
            dfs_from(pc, &mut visited, &mut postorder);
        }

        postorder.reverse();
        postorder
    }

    /// Build def-use chains by finding, for each definition, all uses that
    /// can be reached before another definition of the same register.
    fn build_chains(&mut self, cfg: &ControlFlowGraph) {
        // For each definition, find its uses using reaching definitions
        for (block_pc, block) in &cfg.blocks {
            for (pc, instr) in &block.instructions {
                let (defs, _) = extract_def_use(instr);
                for reg in defs {
                    let def = Definition { pc: *pc, reg };
                    let uses = self.find_uses_for_def(&def, block, cfg);
                    let chain = DefUseChain {
                        definition: def,
                        uses,
                    };
                    self.chains.entry(*block_pc).or_default().push(chain);
                }
            }
        }
    }

    /// Find all uses of a definition within the same block and reaching into successors.
    /// Limits cross-block traversal to avoid quadratic blowup on large functions.
    fn find_uses_for_def(
        &self,
        def: &Definition,
        block: &BasicBlock,
        cfg: &ControlFlowGraph,
    ) -> Vec<Use> {
        let mut uses = Vec::new();
        let mut seen_blocks = HashSet::new();

        // Find uses within the same block after the definition
        let mut found_def = false;
        for (pc, instr) in &block.instructions {
            if *pc == def.pc {
                found_def = true;
                continue;
            }
            if found_def {
                let (instr_defs, instr_uses) = extract_def_use(instr);

                // Check if this instruction uses our register
                if instr_uses.contains(&def.reg) {
                    uses.push(Use {
                        pc: *pc,
                        reg: def.reg,
                    });
                }

                // If this instruction redefines the register, stop searching this path
                if instr_defs.contains(&def.reg) {
                    return uses;
                }
            }
        }

        // Continue searching in successor blocks, with a visit limit
        const MAX_BLOCKS_TO_VISIT: usize = 200;
        seen_blocks.insert(block.start_pc);
        let mut worklist: Vec<usize> = block.successors.clone();

        while let Some(succ_pc) = worklist.pop() {
            if seen_blocks.contains(&succ_pc) {
                continue;
            }
            if seen_blocks.len() >= MAX_BLOCKS_TO_VISIT {
                break;
            }
            seen_blocks.insert(succ_pc);

            if let Some(succ_block) = cfg.blocks.get(&succ_pc) {
                let mut killed = false;
                for (pc, instr) in &succ_block.instructions {
                    let (instr_defs, instr_uses) = extract_def_use(instr);

                    // Check if this instruction uses our register
                    if instr_uses.contains(&def.reg) {
                        uses.push(Use {
                            pc: *pc,
                            reg: def.reg,
                        });
                    }

                    // If this instruction redefines the register, stop searching this path
                    if instr_defs.contains(&def.reg) {
                        killed = true;
                        break;
                    }
                }

                // If not killed, continue to successors
                if !killed {
                    for next_succ in &succ_block.successors {
                        if !seen_blocks.contains(next_succ) {
                            worklist.push(*next_succ);
                        }
                    }
                }
            }
        }

        uses
    }

    /// Get a summary of register activity for display.
    pub fn summarize(&self) -> String {
        let mut output = String::new();
        output.push_str("=== Data Flow Analysis ===\n\n");

        // Count total definitions and uses
        let total_defs: usize = self.defs_at_pc.values().map(|v| v.len()).sum();
        let total_uses: usize = self.uses_at_pc.values().map(|v| v.len()).sum();
        output.push_str(&format!("Total definitions: {}\n", total_defs));
        output.push_str(&format!("Total uses: {}\n\n", total_uses));

        // Show def-use chains
        output.push_str("Def-Use Chains:\n");
        let mut all_chains: Vec<&DefUseChain> = self.chains.values().flatten().collect();
        all_chains.sort_by_key(|c| c.definition.pc);

        for chain in all_chains {
            output.push_str(&format!(
                "  r{} defined @ {:#06x} -> used at: ",
                chain.definition.reg, chain.definition.pc
            ));
            if chain.uses.is_empty() {
                output.push_str("(no uses - dead definition?)\n");
            } else {
                let use_pcs: Vec<String> = chain
                    .uses
                    .iter()
                    .map(|u| format!("{:#06x}", u.pc))
                    .collect();
                output.push_str(&use_pcs.join(", "));
                output.push('\n');
            }
        }

        output
    }
}

/// Compute use[B] and def[B] for a basic block.
/// - use[B] = registers used in B before any definition in B
/// - def[B] = registers defined in B
fn compute_block_use_def(
    block: &BasicBlock,
    defs_at_pc: &HashMap<usize, Vec<u8>>,
    uses_at_pc: &HashMap<usize, Vec<u8>>,
) -> (HashSet<u8>, HashSet<u8>) {
    let mut use_set = HashSet::new();
    let mut def_set = HashSet::new();

    for (pc, _) in &block.instructions {
        // Uses: registers used at this PC that haven't been defined yet in this block
        if let Some(uses) = uses_at_pc.get(pc) {
            for reg in uses {
                if !def_set.contains(reg) {
                    use_set.insert(*reg);
                }
            }
        }

        // Defs: registers defined at this PC
        if let Some(defs) = defs_at_pc.get(pc) {
            for reg in defs {
                def_set.insert(*reg);
            }
        }
    }

    (use_set, def_set)
}

/// Extract which registers are defined and used by an instruction.
/// Returns (defined_registers, used_registers).
fn extract_def_use(instr: &Instruction) -> (Vec<u8>, Vec<u8>) {
    InstructionShape::classify(instr).def_use()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_def_use_add32() {
        let instr = Instruction::Add32 {
            dst: 3,
            src1: 1,
            src2: 2,
        };
        let (defs, uses) = extract_def_use(&instr);
        assert_eq!(defs, vec![3]);
        assert_eq!(uses, vec![1, 2]);
    }

    #[test]
    fn test_extract_def_use_load_imm() {
        let instr = Instruction::LoadImm { reg: 5, value: 42 };
        let (defs, uses) = extract_def_use(&instr);
        assert_eq!(defs, vec![5]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_extract_def_use_store() {
        let instr = Instruction::StoreIndU64 {
            base: 1,
            src: 4,
            offset: 0,
        };
        let (defs, uses) = extract_def_use(&instr);
        assert!(defs.is_empty());
        assert_eq!(uses, vec![1, 4]);
    }

    #[test]
    fn test_extract_def_use_branch() {
        let instr = Instruction::BranchNeImm {
            reg: 2,
            value: 0,
            offset: 10,
        };
        let (defs, uses) = extract_def_use(&instr);
        assert!(defs.is_empty());
        assert_eq!(uses, vec![2]);
    }

    #[test]
    fn test_extract_def_use_ecalli() {
        let instr = Instruction::Ecalli { index: 7 };
        let (defs, uses) = extract_def_use(&instr);
        let all_regs: Vec<u8> = (0..=12).collect();
        assert_eq!(defs, all_regs);
        assert_eq!(uses, all_regs);
    }
}
