//! Instruction Classification
//!
//! Provides a unified classification of PVM instructions into their structural
//! "shapes" (binary op, unary op, load, store, branch, etc.) so that consumers
//! like formatting, lifting, and dataflow analysis can match on ~12 variants
//! instead of ~60 raw instruction variants.
//!
//! This is the single source of truth for how each Instruction maps to its
//! operand structure. Adding a new instruction requires updating only
//! `InstructionShape::classify()`.

use std::fmt;
use wasm_pvm::pvm::Instruction;

/// Binary operator for expression nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    DivU,
    DivS,
    RemU,
    RemS,
    Shl,
    ShrU,
    ShrS,
    And,
    Or,
    Xor,
    LtU,
    LtS,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::DivU => "/u",
            BinOp::DivS => "/s",
            BinOp::RemU => "%u",
            BinOp::RemS => "%s",
            BinOp::Shl => "<<",
            BinOp::ShrU => ">>u",
            BinOp::ShrS => ">>s",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::LtU => "<u",
            BinOp::LtS => "<s",
        };
        write!(f, "{}", s)
    }
}

/// Unary operator for expression nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Sext8,
    Sext16,
    Zext16,
    Popcnt32,
    Popcnt64,
    Clz32,
    Clz64,
    Ctz32,
    Ctz64,
    Sbrk,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            UnaryOp::Not => "!",
            UnaryOp::Sext8 => "sext8",
            UnaryOp::Sext16 => "sext16",
            UnaryOp::Zext16 => "zext16",
            UnaryOp::Popcnt32 => "popcnt32",
            UnaryOp::Popcnt64 => "popcnt64",
            UnaryOp::Clz32 => "clz32",
            UnaryOp::Clz64 => "clz64",
            UnaryOp::Ctz32 => "ctz32",
            UnaryOp::Ctz64 => "ctz64",
            UnaryOp::Sbrk => "sbrk",
        };
        write!(f, "{}", s)
    }
}

/// Memory access width for Load/Store expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemWidth {
    U8,
    I8,
    U16,
    I16,
    U32,
    U64,
}

impl fmt::Display for MemWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MemWidth::U8 => "u8",
            MemWidth::I8 => "i8",
            MemWidth::U16 => "u16",
            MemWidth::I16 => "i16",
            MemWidth::U32 => "u32",
            MemWidth::U64 => "u64",
        };
        write!(f, "{}", s)
    }
}

/// Bit width for arithmetic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitWidth {
    /// 32-bit (or native/unspecified) — no suffix in raw formatting.
    W32,
    /// 64-bit — formatted with "64" suffix in raw mode.
    W64,
}

/// Classified instruction shape, extracting the common structure
/// from PVM instructions for use by formatting, lifting, and dataflow.
///
/// This is the single match over `Instruction` variants. All consumers
/// should use this classification instead of matching on `Instruction` directly.
#[derive(Debug)]
pub enum InstructionShape {
    /// No-op: trap, fallthrough.
    NoOp { name: &'static str },
    /// Load immediate into register.
    LoadImm { dst: u8, value: i64 },
    /// Three-register binary: dst = src1 op src2.
    BinReg {
        op: BinOp,
        width: BitWidth,
        dst: u8,
        src1: u8,
        src2: u8,
    },
    /// Register + immediate binary: dst = src op value.
    BinImm {
        op: BinOp,
        width: BitWidth,
        dst: u8,
        src: u8,
        value: i32,
    },
    /// Unary operation: dst = op(src).
    Unary { op: UnaryOp, dst: u8, src: u8 },
    /// Memory load: dst = width[base + offset].
    Load {
        width: MemWidth,
        dst: u8,
        base: u8,
        offset: i32,
    },
    /// Memory store: width[base + offset] = src.
    Store {
        width: MemWidth,
        base: u8,
        src: u8,
        offset: i32,
    },
    /// Unconditional jump.
    Jump { offset: i32 },
    /// Indirect jump.
    JumpInd { reg: u8 },
    /// Branch with register vs immediate comparison.
    BranchImm {
        cond: &'static str,
        reg: u8,
        value: i32,
        offset: i32,
    },
    /// Branch with two-register comparison.
    BranchReg {
        cond: &'static str,
        reg1: u8,
        reg2: u8,
        offset: i32,
    },
    /// External call.
    Ecalli { index: u32 },
    /// Unknown/unrecognized instruction.
    Unknown { opcode: u8 },
}

impl InstructionShape {
    /// Classify a PVM instruction into its structural shape.
    ///
    /// This is the single source of truth for instruction classification.
    /// When adding a new instruction variant, only this function needs updating.
    pub fn classify(instr: &Instruction) -> Self {
        match instr {
            Instruction::Trap => Self::NoOp { name: "trap" },
            Instruction::Fallthrough => Self::NoOp {
                name: "fallthrough",
            },

            Instruction::LoadImm { reg, value } => Self::LoadImm {
                dst: *reg,
                value: *value as i64,
            },
            Instruction::LoadImm64 { reg, value } => Self::LoadImm {
                dst: *reg,
                value: *value as i64,
            },

            // 32-bit three-register binary ops
            Instruction::Add32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Add,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Sub32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Sub,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Mul32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Mul,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::DivU32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::DivU,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::DivS32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::DivS,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RemU32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RemU,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RemS32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RemS,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::ShloL32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Shl,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::ShloR32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::ShrU,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::SharR32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::ShrS,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },

            // 64-bit three-register binary ops
            Instruction::Add64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Add,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Sub64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Sub,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Mul64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Mul,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::DivU64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::DivU,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::DivS64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::DivS,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RemU64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RemU,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RemS64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RemS,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::ShloL64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Shl,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::ShloR64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::ShrU,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::SharR64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::ShrS,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },

            // Width-agnostic three-register binary ops
            Instruction::And { dst, src1, src2 } => Self::BinReg {
                op: BinOp::And,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Or { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Or,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Xor { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Xor,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::SetLtU { dst, src1, src2 } => Self::BinReg {
                op: BinOp::LtU,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::SetLtS { dst, src1, src2 } => Self::BinReg {
                op: BinOp::LtS,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },

            // Register + immediate binary ops
            Instruction::AddImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::Add,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::AddImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::Add,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SetLtUImm { dst, src, value } => Self::BinImm {
                op: BinOp::LtU,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SetLtSImm { dst, src, value } => Self::BinImm {
                op: BinOp::LtS,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },

            // Unary ops
            Instruction::Sbrk { dst, src } => Self::Unary {
                op: UnaryOp::Sbrk,
                dst: *dst,
                src: *src,
            },
            Instruction::CountSetBits64 { dst, src } => Self::Unary {
                op: UnaryOp::Popcnt64,
                dst: *dst,
                src: *src,
            },
            Instruction::CountSetBits32 { dst, src } => Self::Unary {
                op: UnaryOp::Popcnt32,
                dst: *dst,
                src: *src,
            },
            Instruction::LeadingZeroBits64 { dst, src } => Self::Unary {
                op: UnaryOp::Clz64,
                dst: *dst,
                src: *src,
            },
            Instruction::LeadingZeroBits32 { dst, src } => Self::Unary {
                op: UnaryOp::Clz32,
                dst: *dst,
                src: *src,
            },
            Instruction::TrailingZeroBits64 { dst, src } => Self::Unary {
                op: UnaryOp::Ctz64,
                dst: *dst,
                src: *src,
            },
            Instruction::TrailingZeroBits32 { dst, src } => Self::Unary {
                op: UnaryOp::Ctz32,
                dst: *dst,
                src: *src,
            },
            Instruction::SignExtend8 { dst, src } => Self::Unary {
                op: UnaryOp::Sext8,
                dst: *dst,
                src: *src,
            },
            Instruction::SignExtend16 { dst, src } => Self::Unary {
                op: UnaryOp::Sext16,
                dst: *dst,
                src: *src,
            },
            Instruction::ZeroExtend16 { dst, src } => Self::Unary {
                op: UnaryOp::Zext16,
                dst: *dst,
                src: *src,
            },

            // Load instructions
            Instruction::LoadIndU8 { dst, base, offset } => Self::Load {
                width: MemWidth::U8,
                dst: *dst,
                base: *base,
                offset: *offset,
            },
            Instruction::LoadIndI8 { dst, base, offset } => Self::Load {
                width: MemWidth::I8,
                dst: *dst,
                base: *base,
                offset: *offset,
            },
            Instruction::LoadIndU16 { dst, base, offset } => Self::Load {
                width: MemWidth::U16,
                dst: *dst,
                base: *base,
                offset: *offset,
            },
            Instruction::LoadIndI16 { dst, base, offset } => Self::Load {
                width: MemWidth::I16,
                dst: *dst,
                base: *base,
                offset: *offset,
            },
            Instruction::LoadIndU32 { dst, base, offset } => Self::Load {
                width: MemWidth::U32,
                dst: *dst,
                base: *base,
                offset: *offset,
            },
            Instruction::LoadIndU64 { dst, base, offset } => Self::Load {
                width: MemWidth::U64,
                dst: *dst,
                base: *base,
                offset: *offset,
            },

            // Store instructions
            Instruction::StoreIndU8 { base, src, offset } => Self::Store {
                width: MemWidth::U8,
                base: *base,
                src: *src,
                offset: *offset,
            },
            Instruction::StoreIndU16 { base, src, offset } => Self::Store {
                width: MemWidth::U16,
                base: *base,
                src: *src,
                offset: *offset,
            },
            Instruction::StoreIndU32 { base, src, offset } => Self::Store {
                width: MemWidth::U32,
                base: *base,
                src: *src,
                offset: *offset,
            },
            Instruction::StoreIndU64 { base, src, offset } => Self::Store {
                width: MemWidth::U64,
                base: *base,
                src: *src,
                offset: *offset,
            },

            // Jumps
            Instruction::Jump { offset } => Self::Jump { offset: *offset },
            Instruction::JumpInd { reg, .. } => Self::JumpInd { reg: *reg },

            // Branch with immediate
            Instruction::BranchEqImm { reg, value, offset } => Self::BranchImm {
                cond: "==",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchNeImm { reg, value, offset } => Self::BranchImm {
                cond: "!=",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchGeSImm { reg, value, offset } => Self::BranchImm {
                cond: ">=s",
                reg: *reg,
                value: *value,
                offset: *offset,
            },

            // Branch with two registers
            Instruction::BranchGeU { reg1, reg2, offset } => Self::BranchReg {
                cond: ">=u",
                reg1: *reg1,
                reg2: *reg2,
                offset: *offset,
            },
            Instruction::BranchLtU { reg1, reg2, offset } => Self::BranchReg {
                cond: "<u",
                reg1: *reg1,
                reg2: *reg2,
                offset: *offset,
            },

            // External call
            Instruction::Ecalli { index } => Self::Ecalli { index: *index },

            // Unknown instruction
            Instruction::Unknown { opcode, .. } => Self::Unknown { opcode: *opcode },
        }
    }

    /// Get the destination register defined by this instruction, if any.
    pub fn def_reg(&self) -> Option<u8> {
        match self {
            Self::LoadImm { dst, .. }
            | Self::BinReg { dst, .. }
            | Self::BinImm { dst, .. }
            | Self::Unary { dst, .. }
            | Self::Load { dst, .. } => Some(*dst),
            _ => None,
        }
    }

    /// Extract defined and used registers from the classified instruction.
    pub fn def_use(&self) -> (Vec<u8>, Vec<u8>) {
        match self {
            Self::NoOp { .. } => (vec![], vec![]),
            Self::LoadImm { dst, .. } => (vec![*dst], vec![]),
            Self::BinReg {
                dst, src1, src2, ..
            } => (vec![*dst], vec![*src1, *src2]),
            Self::BinImm { dst, src, .. } => (vec![*dst], vec![*src]),
            Self::Unary { dst, src, .. } => (vec![*dst], vec![*src]),
            Self::Load { dst, base, .. } => (vec![*dst], vec![*base]),
            Self::Store { base, src, .. } => (vec![], vec![*base, *src]),
            Self::Jump { .. } => (vec![], vec![]),
            Self::JumpInd { reg, .. } => (vec![], vec![*reg]),
            Self::BranchImm { reg, .. } => (vec![], vec![*reg]),
            Self::BranchReg { reg1, reg2, .. } => (vec![], vec![*reg1, *reg2]),
            Self::Ecalli { .. } | Self::Unknown { .. } => {
                // Conservatively assume all registers are both read and written.
                let all_regs: Vec<u8> = (0..=12).collect();
                (all_regs.clone(), all_regs)
            }
        }
    }

    /// Format as raw pseudo-code using register names (rN).
    pub fn format_raw(&self) -> String {
        match self {
            Self::NoOp { name } => name.to_string(),
            Self::LoadImm { dst, value } => format!("r{} = {}", dst, value),
            Self::BinReg {
                op,
                width,
                dst,
                src1,
                src2,
            } => {
                let suffix = if *width == BitWidth::W64 { "64" } else { "" };
                format!("r{} = r{} {}{} r{}", dst, src1, op, suffix, src2)
            }
            Self::BinImm {
                op,
                width,
                dst,
                src,
                value,
            } => {
                let suffix = if *width == BitWidth::W64 { "64" } else { "" };
                format!("r{} = r{} {}{} {}", dst, src, op, suffix, value)
            }
            Self::Unary { op, dst, src } => format!("r{} = {}(r{})", dst, op, src),
            Self::Load {
                width,
                dst,
                base,
                offset,
            } => format!("r{} = {}[r{} + {}]", dst, width, base, offset),
            Self::Store {
                width,
                base,
                src,
                offset,
            } => format!("{}[r{} + {}] = r{}", width, base, offset, src),
            Self::Jump { offset } => format!("jump {}", offset),
            Self::JumpInd { reg, .. } => format!("jump_ind r{}", reg),
            Self::BranchImm {
                cond,
                reg,
                value,
                offset,
            } => format!("if (r{} {} {}) jump {}", reg, cond, value, offset),
            Self::BranchReg {
                cond,
                reg1,
                reg2,
                offset,
            } => format!("if (r{} {} r{}) jump {}", reg1, cond, reg2, offset),
            Self::Ecalli { index } => format!("ecalli {}", index),
            Self::Unknown { opcode } => format!("/* unknown opcode {:#04x} */", opcode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_unknown() {
        let instr = Instruction::Unknown {
            opcode: 0xAB,
            raw_bytes: vec![0xAB, 0x01],
        };
        let shape = InstructionShape::classify(&instr);
        assert!(matches!(shape, InstructionShape::Unknown { opcode: 0xAB }));
    }

    #[test]
    fn test_unknown_format_raw() {
        let shape = InstructionShape::Unknown { opcode: 0xFF };
        assert_eq!(shape.format_raw(), "/* unknown opcode 0xff */");
    }

    #[test]
    fn test_unknown_def_use_conservative() {
        let shape = InstructionShape::Unknown { opcode: 0xFF };
        let (defs, uses) = shape.def_use();
        let all_regs: Vec<u8> = (0..=12).collect();
        assert_eq!(defs, all_regs);
        assert_eq!(uses, all_regs);
    }

    #[test]
    fn test_unknown_no_def_reg() {
        let shape = InstructionShape::Unknown { opcode: 0xFF };
        assert_eq!(shape.def_reg(), None);
    }

    #[test]
    fn test_classify_add32() {
        let instr = Instruction::Add32 {
            dst: 3,
            src1: 1,
            src2: 2,
        };
        let shape = InstructionShape::classify(&instr);
        assert!(matches!(
            shape,
            InstructionShape::BinReg {
                op: BinOp::Add,
                width: BitWidth::W32,
                dst: 3,
                src1: 1,
                src2: 2,
            }
        ));
        assert_eq!(shape.format_raw(), "r3 = r1 + r2");
    }

    #[test]
    fn test_classify_add64_format() {
        let instr = Instruction::Add64 {
            dst: 0,
            src1: 1,
            src2: 2,
        };
        let shape = InstructionShape::classify(&instr);
        assert_eq!(shape.format_raw(), "r0 = r1 +64 r2");
    }
}
