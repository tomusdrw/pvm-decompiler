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
#[derive(Debug, Clone)]
pub struct Condition {
    pub op: CondOp,
    pub lhs: Operand,
    pub rhs: Operand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondOp {
    Eq,
    Ne,
    GeS,
    GeU,
    LtU,
}

#[derive(Debug, Clone)]
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
        Instruction::BranchGeSImm { reg, value, .. } => Some(Condition {
            op: CondOp::GeS,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGeU { reg1, reg2, .. } => Some(Condition {
            op: CondOp::GeU,
            lhs: Operand::Reg(*reg1),
            rhs: Operand::Reg(*reg2),
        }),
        Instruction::BranchLtU { reg1, reg2, .. } => Some(Condition {
            op: CondOp::LtU,
            lhs: Operand::Reg(*reg1),
            rhs: Operand::Reg(*reg2),
        }),
        _ => None,
    }
}
