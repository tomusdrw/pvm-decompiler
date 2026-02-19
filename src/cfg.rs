use crate::decoder::DecodedProgram;
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
            match instr {
                Instruction::Jump { offset } => {
                    // Target is a leader
                    let target_pc = Self::compute_jump_target(*pc, *offset);
                    leaders.insert(target_pc);
                    // Next instruction (if exists) is a leader (unreachable, but mark it)
                    // Actually, Jump is unconditional, so next is unreachable
                    // But we still mark it for completeness
                }
                Instruction::JumpInd { .. } => {
                    // Indirect jump: target is unknown, treat as potential return
                    // Don't add any specific leader
                }
                Instruction::BranchEqImm { offset, .. }
                | Instruction::BranchNeImm { offset, .. }
                | Instruction::BranchGeSImm { offset, .. }
                | Instruction::BranchGeU { offset, .. }
                | Instruction::BranchLtU { offset, .. } => {
                    // Branch target is a leader
                    let target_pc = Self::compute_jump_target(*pc, *offset);
                    leaders.insert(target_pc);
                    // Fallthrough (next instruction) is also a leader
                    // We'll compute this in the next pass
                }
                Instruction::Trap => {
                    // Trap terminates, no fallthrough
                }
                Instruction::Fallthrough => {
                    // Fallthrough continues to next
                }
                _ => {
                    // Regular instruction, continues to next
                }
            }
        }

        // Add fallthrough points: the instruction after each terminator
        for i in 0..program.instructions.len() {
            let (_pc, instr) = &program.instructions[i];
            let is_terminator = matches!(
                instr,
                Instruction::Jump { .. }
                    | Instruction::BranchEqImm { .. }
                    | Instruction::BranchNeImm { .. }
                    | Instruction::BranchGeSImm { .. }
                    | Instruction::BranchGeU { .. }
                    | Instruction::BranchLtU { .. }
                    | Instruction::Trap
            );

            if is_terminator && i + 1 < program.instructions.len() {
                let (next_pc, _) = program.instructions[i + 1];
                // Always add next instruction as leader if current is terminator
                // This ensures separate blocks even for unreachable code
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
                // Last block extends to end of code
                program
                    .instructions
                    .last()
                    .map(|(pc, _instr)| {
                        // Estimate end PC (this is approximate)
                        pc + 1 // Simplified: assume 1 byte per instruction
                    })
                    .unwrap_or(0)
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

        // For each block, determine successors based on terminator
        for block_idx in 0..blocks.len() {
            let block = &blocks[block_idx];
            let successors = if let Some((term_pc, terminator)) = block.instructions.last() {
                match terminator {
                    Instruction::Jump { offset } => {
                        // Unconditional jump: single successor
                        let target_pc = Self::compute_jump_target(*term_pc, *offset);
                        if let Some(&succ_idx) = pc_to_block_idx.get(&target_pc) {
                            vec![blocks[succ_idx].start_pc]
                        } else {
                            vec![]
                        }
                    }
                    Instruction::BranchEqImm { offset, .. }
                    | Instruction::BranchNeImm { offset, .. }
                    | Instruction::BranchGeSImm { offset, .. }
                    | Instruction::BranchGeU { offset, .. }
                    | Instruction::BranchLtU { offset, .. } => {
                        // Conditional branch: two successors (target and fallthrough)
                        let target_pc = Self::compute_jump_target(*term_pc, *offset);
                        let mut succs = Vec::new();

                        // Add target
                        if let Some(&succ_idx) = pc_to_block_idx.get(&target_pc) {
                            succs.push(blocks[succ_idx].start_pc);
                        }

                        // Add fallthrough (next block)
                        if block_idx + 1 < blocks.len() {
                            succs.push(blocks[block_idx + 1].start_pc);
                        }

                        succs
                    }
                    Instruction::Trap => {
                        // No successors
                        vec![]
                    }
                    Instruction::Fallthrough => {
                        // Explicit fallthrough to next block
                        if block_idx + 1 < blocks.len() {
                            vec![blocks[block_idx + 1].start_pc]
                        } else {
                            vec![]
                        }
                    }
                    _ => {
                        // Regular instruction: fallthrough to next block
                        if block_idx + 1 < blocks.len() {
                            vec![blocks[block_idx + 1].start_pc]
                        } else {
                            vec![]
                        }
                    }
                }
            } else {
                // Empty block? Fallthrough
                if block_idx + 1 < blocks.len() {
                    vec![blocks[block_idx + 1].start_pc]
                } else {
                    vec![]
                }
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
    fn compute_jump_target(current_pc: usize, offset: i32) -> usize {
        if offset >= 0 {
            current_pc + offset as usize
        } else {
            current_pc.saturating_sub((-offset) as usize)
        }
    }
}
