//! Data Flow Analysis for PVM Disassembler
//!
//! This module provides def-use chain analysis to track register definitions
//! and their uses across basic blocks. This is foundational for:
//! - Variable recovery (registers → high-level variables)
//! - Dead code detection
//! - Constant propagation preparation
//! - Understanding data dependencies

use crate::cfg::{BasicBlock, ControlFlowGraph};
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
    fn compute_liveness(&mut self, cfg: &ControlFlowGraph) {
        // Initialize live_in and live_out as empty for all blocks
        for block_pc in cfg.blocks.keys() {
            self.live_in.insert(*block_pc, HashSet::new());
            self.live_out.insert(*block_pc, HashSet::new());
        }

        // Compute use[B] and def[B] for each block
        let mut block_use: HashMap<usize, HashSet<u8>> = HashMap::new();
        let mut block_def: HashMap<usize, HashSet<u8>> = HashMap::new();

        for (block_pc, block) in &cfg.blocks {
            let (uses, defs) = compute_block_use_def(block, &self.defs_at_pc, &self.uses_at_pc);
            block_use.insert(*block_pc, uses);
            block_def.insert(*block_pc, defs);
        }

        // Iterate until fixed point
        let mut changed = true;
        while changed {
            changed = false;

            for (block_pc, block) in &cfg.blocks {
                // live_out[B] = ∪ live_in[S] for all successors S
                let mut new_live_out = HashSet::new();
                for succ_pc in &block.successors {
                    if let Some(succ_live_in) = self.live_in.get(succ_pc) {
                        new_live_out.extend(succ_live_in.iter().copied());
                    }
                }

                // live_in[B] = use[B] ∪ (live_out[B] - def[B])
                let use_b = block_use.get(block_pc).cloned().unwrap_or_default();
                let def_b = block_def.get(block_pc).cloned().unwrap_or_default();
                let live_out_minus_def: HashSet<u8> =
                    new_live_out.difference(&def_b).copied().collect();
                let new_live_in: HashSet<u8> = use_b.union(&live_out_minus_def).copied().collect();

                // Check for changes
                let old_live_in = self.live_in.get(block_pc).cloned().unwrap_or_default();
                let old_live_out = self.live_out.get(block_pc).cloned().unwrap_or_default();

                if new_live_in != old_live_in || new_live_out != old_live_out {
                    changed = true;
                    self.live_in.insert(*block_pc, new_live_in);
                    self.live_out.insert(*block_pc, new_live_out);
                }
            }
        }
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

        // Continue searching in successor blocks
        seen_blocks.insert(block.start_pc);
        let mut worklist: Vec<usize> = block.successors.clone();

        while let Some(succ_pc) = worklist.pop() {
            if seen_blocks.contains(&succ_pc) {
                continue;
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
    match instr {
        // No defs, no uses
        Instruction::Trap | Instruction::Fallthrough => (vec![], vec![]),

        // Immediate loads: define dst, no uses
        Instruction::LoadImm64 { reg, .. } | Instruction::LoadImm { reg, .. } => {
            (vec![*reg], vec![])
        }

        // Three-register ops: dst = src1 op src2
        Instruction::Add32 { dst, src1, src2 }
        | Instruction::Sub32 { dst, src1, src2 }
        | Instruction::Mul32 { dst, src1, src2 }
        | Instruction::DivU32 { dst, src1, src2 }
        | Instruction::DivS32 { dst, src1, src2 }
        | Instruction::RemU32 { dst, src1, src2 }
        | Instruction::RemS32 { dst, src1, src2 }
        | Instruction::ShloL32 { dst, src1, src2 }
        | Instruction::ShloR32 { dst, src1, src2 }
        | Instruction::SharR32 { dst, src1, src2 }
        | Instruction::Add64 { dst, src1, src2 }
        | Instruction::Sub64 { dst, src1, src2 }
        | Instruction::Mul64 { dst, src1, src2 }
        | Instruction::DivU64 { dst, src1, src2 }
        | Instruction::DivS64 { dst, src1, src2 }
        | Instruction::RemU64 { dst, src1, src2 }
        | Instruction::RemS64 { dst, src1, src2 }
        | Instruction::ShloL64 { dst, src1, src2 }
        | Instruction::ShloR64 { dst, src1, src2 }
        | Instruction::SharR64 { dst, src1, src2 }
        | Instruction::And { dst, src1, src2 }
        | Instruction::Xor { dst, src1, src2 }
        | Instruction::Or { dst, src1, src2 }
        | Instruction::SetLtU { dst, src1, src2 }
        | Instruction::SetLtS { dst, src1, src2 } => (vec![*dst], vec![*src1, *src2]),

        // Two-register ops: dst = op(src)
        Instruction::Sbrk { dst, src }
        | Instruction::CountSetBits64 { dst, src }
        | Instruction::CountSetBits32 { dst, src }
        | Instruction::LeadingZeroBits64 { dst, src }
        | Instruction::LeadingZeroBits32 { dst, src }
        | Instruction::TrailingZeroBits64 { dst, src }
        | Instruction::TrailingZeroBits32 { dst, src }
        | Instruction::SignExtend8 { dst, src }
        | Instruction::SignExtend16 { dst, src }
        | Instruction::ZeroExtend16 { dst, src } => (vec![*dst], vec![*src]),

        // Register + immediate ops: dst = src op imm
        Instruction::AddImm32 { dst, src, .. }
        | Instruction::AddImm64 { dst, src, .. }
        | Instruction::SetLtUImm { dst, src, .. }
        | Instruction::SetLtSImm { dst, src, .. } => (vec![*dst], vec![*src]),

        // Jumps: no defs (except pc), uses depend on instruction
        Instruction::Jump { .. } => (vec![], vec![]),
        Instruction::JumpInd { reg, .. } => (vec![], vec![*reg]),

        // Load instructions: dst = mem[base + offset]
        Instruction::LoadIndU8 { dst, base, .. }
        | Instruction::LoadIndI8 { dst, base, .. }
        | Instruction::LoadIndU16 { dst, base, .. }
        | Instruction::LoadIndI16 { dst, base, .. }
        | Instruction::LoadIndU32 { dst, base, .. }
        | Instruction::LoadIndU64 { dst, base, .. } => (vec![*dst], vec![*base]),

        // Store instructions: mem[base + offset] = src
        Instruction::StoreIndU8 { base, src, .. }
        | Instruction::StoreIndU16 { base, src, .. }
        | Instruction::StoreIndU32 { base, src, .. }
        | Instruction::StoreIndU64 { base, src, .. } => (vec![], vec![*base, *src]),

        // Branch instructions: use reg (and comparison target), no defs
        Instruction::BranchEqImm { reg, .. }
        | Instruction::BranchNeImm { reg, .. }
        | Instruction::BranchGeSImm { reg, .. } => (vec![], vec![*reg]),

        Instruction::BranchGeU { reg1, reg2, .. } | Instruction::BranchLtU { reg1, reg2, .. } => {
            (vec![], vec![*reg1, *reg2])
        }

        // System call: conservatively assume all registers are both read and written.
        // The PVM calling convention passes args and returns values in registers,
        // and we don't know which registers a given ecalli uses, so we must assume
        // all 13 registers (r0-r12) are both used and defined.
        Instruction::Ecalli { .. } => {
            let all_regs: Vec<u8> = (0..=12).collect();
            (all_regs.clone(), all_regs)
        }
    }
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
