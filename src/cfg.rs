use crate::decoder::DecodedProgram;
use crate::instruction::InstructionShape;
use std::collections::{HashMap, HashSet};
use wasm_pvm::pvm::Instruction;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub end_pc: usize,                           // Exclusive
    pub instructions: Vec<(usize, Instruction)>, // (PC, Instruction)
    pub successors: Vec<usize>,                  // List of start_pc of successor blocks
    pub predecessors: Vec<usize>,                // List of start_pc of predecessor blocks
}

#[derive(Debug)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<usize, BasicBlock>,
    pub entry_pc: usize,
}

impl ControlFlowGraph {
    pub fn new(entry_pc: usize) -> Self {
        Self {
            blocks: HashMap::new(),
            entry_pc,
        }
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.start_pc, block);
    }

    /// Build a CFG from a decoded program.
    ///
    /// Algorithm:
    /// 1. Identify leaders (PCs where blocks start)
    /// 2. Create blocks by grouping instructions between leaders
    /// 3. Connect blocks by analyzing terminators (jumps, branches, etc.)
    pub fn build(program: &DecodedProgram) -> Self {
        let mut cfg = ControlFlowGraph::new(0);

        if program.instructions.is_empty() {
            return cfg;
        }

        // Step 1: Identify leaders
        let leaders = Self::identify_leaders(program);

        // Step 2: Create blocks
        let blocks = Self::create_blocks(program, &leaders);

        // Step 3: Connect blocks (add edges)
        let blocks = Self::connect_blocks(program, blocks, &leaders);

        // Add blocks to CFG
        for block in blocks {
            cfg.add_block(block);
        }

        cfg
    }

    /// Step 1: Identify all leader PCs (block start points).
    fn identify_leaders(program: &DecodedProgram) -> HashSet<usize> {
        let mut leaders = HashSet::new();

        // PC 0 is always a leader
        leaders.insert(0);

        // Scan instructions to find jump/branch targets and fallthrough points
        for (pc, instr) in &program.instructions {
            let shape = InstructionShape::classify(instr);
            if let Some(offset) = shape.branch_offset() {
                let target_pc = Self::compute_jump_target(*pc, offset);
                leaders.insert(target_pc);
            }
        }

        // Add fallthrough points: the instruction after each terminator
        for i in 0..program.instructions.len() {
            let (_pc, instr) = &program.instructions[i];
            let shape = InstructionShape::classify(instr);

            if shape.is_terminator() && i + 1 < program.instructions.len() {
                let (next_pc, _) = program.instructions[i + 1];
                leaders.insert(next_pc);
            }
        }

        leaders
    }

    /// Step 2: Create basic blocks from leaders.
    fn create_blocks(program: &DecodedProgram, leaders: &HashSet<usize>) -> Vec<BasicBlock> {
        let mut blocks = Vec::new();
        let mut sorted_leaders: Vec<usize> = leaders.iter().copied().collect();
        sorted_leaders.sort();

        for i in 0..sorted_leaders.len() {
            let start_pc = sorted_leaders[i];
            let end_pc = if i + 1 < sorted_leaders.len() {
                sorted_leaders[i + 1]
            } else {
                // Last block extends to end of code section
                program.code_len
            };

            // Collect instructions in this block
            let mut block_instrs = Vec::new();
            for (pc, instr) in &program.instructions {
                if *pc >= start_pc && *pc < end_pc {
                    block_instrs.push((*pc, instr.clone()));
                }
            }

            if !block_instrs.is_empty() {
                let block = BasicBlock {
                    start_pc,
                    end_pc,
                    instructions: block_instrs,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                };
                blocks.push(block);
            }
        }

        blocks
    }

    /// Step 3: Connect blocks by analyzing terminators.
    fn connect_blocks(
        _program: &DecodedProgram,
        mut blocks: Vec<BasicBlock>,
        _leaders: &HashSet<usize>,
    ) -> Vec<BasicBlock> {
        // Build a map of start_pc -> block index for quick lookup
        let mut pc_to_block_idx: HashMap<usize, usize> = HashMap::new();
        for (idx, block) in blocks.iter().enumerate() {
            pc_to_block_idx.insert(block.start_pc, idx);
        }

        // Pre-compute fallthrough targets for each block index
        let fallthrough_pcs: Vec<Option<usize>> = (0..blocks.len())
            .map(|idx| {
                if idx + 1 < blocks.len() {
                    Some(blocks[idx + 1].start_pc)
                } else {
                    None
                }
            })
            .collect();

        // For each block, determine successors based on terminator
        for block_idx in 0..blocks.len() {
            let block = &blocks[block_idx];
            let successors = if let Some((term_pc, terminator)) = block.instructions.last() {
                let shape = InstructionShape::classify(terminator);

                if let Some(offset) = shape.branch_offset() {
                    let target_pc = Self::compute_jump_target(*term_pc, offset);
                    let mut succs = Vec::new();

                    // Add branch/jump target
                    if let Some(&succ_idx) = pc_to_block_idx.get(&target_pc) {
                        succs.push(blocks[succ_idx].start_pc);
                    }

                    // Conditional branches also fall through
                    if shape.is_conditional_branch() {
                        succs.extend(fallthrough_pcs[block_idx]);
                    }

                    succs
                } else if matches!(shape, InstructionShape::NoOp { name: "trap" })
                    || matches!(shape, InstructionShape::JumpInd { .. })
                {
                    // Trap and indirect jumps have no static successors
                    vec![]
                } else {
                    // All other instructions (including fallthrough, regular ops): fall through
                    fallthrough_pcs[block_idx].into_iter().collect()
                }
            } else {
                fallthrough_pcs[block_idx].into_iter().collect()
            };

            blocks[block_idx].successors = successors;
        }

        // Compute predecessors from successors
        let mut predecessors: HashMap<usize, Vec<usize>> = HashMap::new();
        for block in &blocks {
            for &succ_pc in &block.successors {
                predecessors
                    .entry(succ_pc)
                    .or_default()
                    .push(block.start_pc);
            }
        }

        for block in &mut blocks {
            block.predecessors = predecessors
                .get(&block.start_pc)
                .cloned()
                .unwrap_or_default();
        }

        blocks
    }

    /// Compute the target PC of a jump/branch instruction.
    /// Offset is relative to the start of the instruction.
    pub fn compute_jump_target(current_pc: usize, offset: i32) -> usize {
        if offset >= 0 {
            current_pc + offset as usize
        } else {
            current_pc.saturating_sub((-offset) as usize)
        }
    }
}

/// Test helper: build a CFG from a list of (start_pc, instructions, successors).
/// Predecessors are computed automatically from the successor lists.
#[cfg(test)]
pub fn build_test_cfg(
    entry: usize,
    blocks: Vec<(usize, Vec<(usize, Instruction)>, Vec<usize>)>,
) -> ControlFlowGraph {
    let mut cfg = ControlFlowGraph::new(entry);
    let mut all_blocks: Vec<BasicBlock> = Vec::new();

    for (start_pc, instructions, successors) in &blocks {
        let end_pc = instructions
            .last()
            .map(|(pc, _)| pc + 1)
            .unwrap_or(*start_pc);
        all_blocks.push(BasicBlock {
            start_pc: *start_pc,
            end_pc,
            instructions: instructions.clone(),
            successors: successors.clone(),
            predecessors: Vec::new(),
        });
    }

    // Compute predecessors from successors.
    let successor_map: Vec<(usize, Vec<usize>)> = all_blocks
        .iter()
        .map(|b| (b.start_pc, b.successors.clone()))
        .collect();
    for (src_pc, succs) in &successor_map {
        for &succ_pc in succs {
            if let Some(b) = all_blocks.iter_mut().find(|b| b.start_pc == succ_pc) {
                b.predecessors.push(*src_pc);
            }
        }
    }

    for b in all_blocks {
        cfg.add_block(b);
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::DecodedProgram;

    #[test]
    fn test_build_linear_cfg() {
        // A -> B -> C (via Jump)
        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![
                (0, Instruction::LoadImm { reg: 0, value: 1 }),
                (4, Instruction::Jump { offset: 4 }),
                (9, Instruction::LoadImm { reg: 1, value: 2 }),
                (13, Instruction::Trap),
            ],
            code_len: 14,
        };
        let cfg = ControlFlowGraph::build(&program);

        // Should have blocks starting at: 0 (entry), 9 (after jump)
        assert!(cfg.blocks.contains_key(&0));
        assert!(cfg.blocks.contains_key(&9));
    }

    #[test]
    fn test_build_branch_cfg() {
        // Block 0: branch -> targets at 7 and fallthrough at 7 too (or wherever)
        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![
                (0, Instruction::LoadImm { reg: 0, value: 42 }),
                (
                    4,
                    Instruction::BranchNeImm {
                        reg: 0,
                        value: 0,
                        offset: 10,
                    },
                ),
                (10, Instruction::LoadImm { reg: 1, value: 1 }),
                (14, Instruction::Trap),
            ],
            code_len: 15,
        };
        let cfg = ControlFlowGraph::build(&program);

        // Entry block at 0, branch target at 14 (4+10), fallthrough at 10
        assert!(cfg.blocks.contains_key(&0));
        assert!(cfg.blocks.contains_key(&10));

        // The block at 0 should have 2 successors (branch target and fallthrough)
        let entry = cfg.blocks.get(&0).unwrap();
        assert_eq!(
            entry.successors.len(),
            2,
            "Branch should produce 2 successors, got: {:?}",
            entry.successors
        );
    }

    #[test]
    fn test_predecessors_computed() {
        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![
                (0, Instruction::LoadImm { reg: 0, value: 1 }),
                (
                    4,
                    Instruction::BranchNeImm {
                        reg: 0,
                        value: 0,
                        offset: 10,
                    },
                ),
                (10, Instruction::LoadImm { reg: 1, value: 2 }),
                (14, Instruction::Trap),
            ],
            code_len: 15,
        };
        let cfg = ControlFlowGraph::build(&program);

        // Block at 10 should have block 0 as predecessor
        let block_10 = cfg.blocks.get(&10).unwrap();
        assert!(
            block_10.predecessors.contains(&0),
            "Block 10 should have 0 as predecessor"
        );
    }

    #[test]
    fn test_empty_program() {
        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![],
            code_len: 0,
        };
        let cfg = ControlFlowGraph::build(&program);
        assert!(cfg.blocks.is_empty());
    }

    #[test]
    fn test_compute_jump_target() {
        assert_eq!(ControlFlowGraph::compute_jump_target(10, 5), 15);
        assert_eq!(ControlFlowGraph::compute_jump_target(10, -3), 7);
        assert_eq!(ControlFlowGraph::compute_jump_target(10, 0), 10);
        // Saturating: doesn't underflow
        assert_eq!(ControlFlowGraph::compute_jump_target(2, -100), 0);
    }

    #[test]
    fn test_trap_terminates_block() {
        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![
                (0, Instruction::LoadImm { reg: 0, value: 1 }),
                (4, Instruction::Trap),
                (5, Instruction::LoadImm { reg: 1, value: 2 }),
            ],
            code_len: 9,
        };
        let cfg = ControlFlowGraph::build(&program);

        // Block containing trap should have no successors
        let entry = cfg.blocks.get(&0).unwrap();
        assert!(
            entry.successors.is_empty(),
            "Trap block should have no successors"
        );
    }

    #[test]
    fn test_last_block_end_pc_uses_code_len() {
        // Instructions at PC 0 (4 bytes) and PC 4 (5 bytes) => code_len = 9
        let program = DecodedProgram {
            jump_table: vec![],
            instructions: vec![
                (0, Instruction::LoadImm { reg: 0, value: 1 }),
                (4, Instruction::Jump { offset: -4 }),
            ],
            code_len: 9,
        };
        let cfg = ControlFlowGraph::build(&program);

        // The block containing the Jump should have end_pc = 9 (code_len), not 5 (pc + 1)
        let block = cfg.blocks.get(&0).unwrap();
        assert_eq!(block.end_pc, 9, "Last block end_pc should equal code_len");
    }
}
