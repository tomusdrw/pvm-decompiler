//! Structural Analysis - Recover High-Level Control Structures from CFG
//!
//! Detects loops, if-then-else, and switch/case patterns from the control flow
//! graph and produces pseudo-code output for human-readable disassembly.

mod analysis;
mod emission;

pub use analysis::DominatorTree;

use std::collections::HashSet;
use wasm_pvm::pvm::Instruction;

/// Function signature information for pseudo-code emission.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// Function name (e.g., "func_0", "main").
    pub name: String,
    /// Parameter register numbers, sorted.
    pub params: Vec<u8>,
}

/// A recovered high-level control structure.
#[derive(Debug, Clone)]
pub enum Structure {
    /// A natural loop: header block dominates latch, latch has back-edge to header.
    Loop {
        header: usize,
        latch: usize,
        body: HashSet<usize>,
        condition: Option<Condition>,
    },
    /// An if-then-else (diamond) or if-then (triangle) pattern.
    IfThenElse {
        header: usize,
        then_blocks: Vec<usize>,
        else_blocks: Vec<usize>, // empty for if-then (triangle)
        join: Option<usize>,
        condition: Option<Condition>,
    },
    /// A switch/case via indirect jump table.
    Switch {
        header: usize,
        reg: u8,
        cases: Vec<(Vec<u32>, usize)>, // (case values, target block PC)
        is_dispatch: bool,             // true if this is PVM dispatch infrastructure
    },
}

/// A branch condition extracted from a terminator instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub op: CondOp,
    pub lhs: Operand,
    pub rhs: Operand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondOp {
    Eq,
    Ne,
    LtS,
    LeS,
    GeS,
    GtS,
    LeU,
    GeU,
    LtU,
    GtU,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Reg(u8),
    Imm(i32),
}

/// Result of structural analysis.
#[derive(Debug)]
pub struct StructuralAnalysis {
    pub structures: Vec<Structure>,
    pub dom_tree: DominatorTree,
}

/// Extract a branch condition from a terminator instruction.
pub(crate) fn extract_condition(instr: &Instruction) -> Option<Condition> {
    match instr {
        Instruction::BranchEqImm { reg, value, .. } => Some(Condition {
            op: CondOp::Eq,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchNeImm { reg, value, .. } => Some(Condition {
            op: CondOp::Ne,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchLtSImm { reg, value, .. } => Some(Condition {
            op: CondOp::LtS,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchLeSImm { reg, value, .. } => Some(Condition {
            op: CondOp::LeS,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGeSImm { reg, value, .. } => Some(Condition {
            op: CondOp::GeS,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGtSImm { reg, value, .. } => Some(Condition {
            op: CondOp::GtS,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchLeUImm { reg, value, .. } => Some(Condition {
            op: CondOp::LeU,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGeUImm { reg, value, .. } => Some(Condition {
            op: CondOp::GeU,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchLtUImm { reg, value, .. } => Some(Condition {
            op: CondOp::LtU,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGtUImm { reg, value, .. } => Some(Condition {
            op: CondOp::GtU,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        // PVM convention: BranchOp { reg1: a, reg2: b } branches when b op a.
        // So we swap operands: lhs=reg2, rhs=reg1.
        Instruction::BranchEq { reg1, reg2, .. } => Some(Condition {
            op: CondOp::Eq,
            lhs: Operand::Reg(*reg2),
            rhs: Operand::Reg(*reg1),
        }),
        Instruction::BranchNe { reg1, reg2, .. } => Some(Condition {
            op: CondOp::Ne,
            lhs: Operand::Reg(*reg2),
            rhs: Operand::Reg(*reg1),
        }),
        Instruction::BranchLtS { reg1, reg2, .. } => Some(Condition {
            op: CondOp::LtS,
            lhs: Operand::Reg(*reg2),
            rhs: Operand::Reg(*reg1),
        }),
        Instruction::BranchGeS { reg1, reg2, .. } => Some(Condition {
            op: CondOp::GeS,
            lhs: Operand::Reg(*reg2),
            rhs: Operand::Reg(*reg1),
        }),
        Instruction::BranchGeU { reg1, reg2, .. } => Some(Condition {
            op: CondOp::GeU,
            lhs: Operand::Reg(*reg2),
            rhs: Operand::Reg(*reg1),
        }),
        Instruction::BranchLtU { reg1, reg2, .. } => Some(Condition {
            op: CondOp::LtU,
            lhs: Operand::Reg(*reg2),
            rhs: Operand::Reg(*reg1),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_condition_supports_all_branch_variants() {
        let cases = vec![
            (
                Instruction::BranchEqImm {
                    reg: 1,
                    value: 11,
                    offset: 4,
                },
                CondOp::Eq,
                Operand::Reg(1),
                Operand::Imm(11),
            ),
            (
                Instruction::BranchNeImm {
                    reg: 2,
                    value: 12,
                    offset: 4,
                },
                CondOp::Ne,
                Operand::Reg(2),
                Operand::Imm(12),
            ),
            (
                Instruction::BranchLtSImm {
                    reg: 3,
                    value: 13,
                    offset: 4,
                },
                CondOp::LtS,
                Operand::Reg(3),
                Operand::Imm(13),
            ),
            (
                Instruction::BranchLeSImm {
                    reg: 4,
                    value: 14,
                    offset: 4,
                },
                CondOp::LeS,
                Operand::Reg(4),
                Operand::Imm(14),
            ),
            (
                Instruction::BranchGeSImm {
                    reg: 5,
                    value: 15,
                    offset: 4,
                },
                CondOp::GeS,
                Operand::Reg(5),
                Operand::Imm(15),
            ),
            (
                Instruction::BranchGtSImm {
                    reg: 6,
                    value: 16,
                    offset: 4,
                },
                CondOp::GtS,
                Operand::Reg(6),
                Operand::Imm(16),
            ),
            (
                Instruction::BranchLtUImm {
                    reg: 7,
                    value: 17,
                    offset: 4,
                },
                CondOp::LtU,
                Operand::Reg(7),
                Operand::Imm(17),
            ),
            (
                Instruction::BranchLeUImm {
                    reg: 8,
                    value: 18,
                    offset: 4,
                },
                CondOp::LeU,
                Operand::Reg(8),
                Operand::Imm(18),
            ),
            (
                Instruction::BranchGeUImm {
                    reg: 9,
                    value: 19,
                    offset: 4,
                },
                CondOp::GeU,
                Operand::Reg(9),
                Operand::Imm(19),
            ),
            (
                Instruction::BranchGtUImm {
                    reg: 10,
                    value: 20,
                    offset: 4,
                },
                CondOp::GtU,
                Operand::Reg(10),
                Operand::Imm(20),
            ),
            // PVM convention: BranchOp { reg1: a, reg2: b } branches when b op a.
            // So extracted condition has lhs=reg2, rhs=reg1.
            (
                Instruction::BranchEq {
                    reg1: 1,
                    reg2: 2,
                    offset: 4,
                },
                CondOp::Eq,
                Operand::Reg(2),
                Operand::Reg(1),
            ),
            (
                Instruction::BranchNe {
                    reg1: 2,
                    reg2: 3,
                    offset: 4,
                },
                CondOp::Ne,
                Operand::Reg(3),
                Operand::Reg(2),
            ),
            (
                Instruction::BranchLtS {
                    reg1: 3,
                    reg2: 4,
                    offset: 4,
                },
                CondOp::LtS,
                Operand::Reg(4),
                Operand::Reg(3),
            ),
            (
                Instruction::BranchGeS {
                    reg1: 4,
                    reg2: 5,
                    offset: 4,
                },
                CondOp::GeS,
                Operand::Reg(5),
                Operand::Reg(4),
            ),
            (
                Instruction::BranchLtU {
                    reg1: 5,
                    reg2: 6,
                    offset: 4,
                },
                CondOp::LtU,
                Operand::Reg(6),
                Operand::Reg(5),
            ),
            (
                Instruction::BranchGeU {
                    reg1: 6,
                    reg2: 7,
                    offset: 4,
                },
                CondOp::GeU,
                Operand::Reg(7),
                Operand::Reg(6),
            ),
        ];

        for (instr, expected_op, expected_lhs, expected_rhs) in cases {
            let cond = extract_condition(&instr).expect("branch should extract condition");
            assert_eq!(cond.op, expected_op);
            assert_eq!(cond.lhs, expected_lhs);
            assert_eq!(cond.rhs, expected_rhs);
        }
    }
}
