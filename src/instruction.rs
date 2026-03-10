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
    /// Greater-than-or-equal unsigned — produced by simplification of `!(x <u y)`.
    GeU,
    /// Greater-than-or-equal signed — produced by simplification of `!(x <s y)`.
    GeS,
    /// Greater-than unsigned — produced by flipping `const <u expr` → `expr >u const`.
    GtU,
    /// Greater-than signed — produced by flipping `const <s expr` → `expr >s const`.
    GtS,
    /// Less-than-or-equal unsigned — produced by inversion of `!(x >u y)`.
    LeU,
    /// Less-than-or-equal signed — produced by inversion of `!(x >s y)`.
    LeS,
    /// Negate and add: dst = value - src.
    NegAdd,
    /// Rotate left.
    RotL,
    /// Rotate right.
    RotR,
    /// Upper 64 bits of signed×signed 128-bit multiply.
    MulUpperSS,
    /// Upper 64 bits of unsigned×unsigned 128-bit multiply.
    MulUpperUU,
    /// Upper 64 bits of signed×unsigned 128-bit multiply.
    MulUpperSU,
    /// AND with inverted second operand: dst = src1 & ~src2.
    AndInv,
    /// OR with inverted second operand: dst = src1 | ~src2.
    OrInv,
    /// XNOR: dst = ~(src1 ^ src2).
    Xnor,
    /// Signed maximum.
    Max,
    /// Unsigned maximum.
    MaxU,
    /// Signed minimum.
    Min,
    /// Unsigned minimum.
    MinU,
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
            BinOp::GeU => ">=u",
            BinOp::GeS => ">=s",
            BinOp::GtU => ">u",
            BinOp::GtS => ">s",
            BinOp::LeU => "<=u",
            BinOp::LeS => "<=s",
            BinOp::NegAdd => "neg+",
            BinOp::RotL => "rotl",
            BinOp::RotR => "rotr",
            BinOp::MulUpperSS => "mulhss",
            BinOp::MulUpperUU => "mulhuu",
            BinOp::MulUpperSU => "mulhsu",
            BinOp::AndInv => "&~",
            BinOp::OrInv => "|~",
            BinOp::Xnor => "xnor",
            BinOp::Max => "max",
            BinOp::MaxU => "maxu",
            BinOp::Min => "min",
            BinOp::MinU => "minu",
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
    /// Reverse byte order (bswap).
    Bswap,
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
            UnaryOp::Bswap => "bswap",
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
    I32,
    U64,
}

impl MemWidth {
    /// Return the byte size of this memory width.
    pub fn byte_size(self) -> i64 {
        match self {
            MemWidth::U8 | MemWidth::I8 => 1,
            MemWidth::U16 | MemWidth::I16 => 2,
            MemWidth::U32 | MemWidth::I32 => 4,
            MemWidth::U64 => 8,
        }
    }
}

impl fmt::Display for MemWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MemWidth::U8 => "u8",
            MemWidth::I8 => "i8",
            MemWidth::U16 => "u16",
            MemWidth::I16 => "i16",
            MemWidth::U32 => "u32",
            MemWidth::I32 => "i32",
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
    /// Register + immediate binary with reversed operands: dst = value op src.
    BinImmRev {
        op: BinOp,
        width: BitWidth,
        dst: u8,
        src: u8,
        value: i32,
    },
    /// Conditional move (three registers): if cond then dst = src.
    CmovReg {
        is_zero: bool,
        dst: u8,
        src: u8,
        cond: u8,
    },
    /// Conditional move with immediate: if cond then dst = value.
    CmovImm {
        is_zero: bool,
        dst: u8,
        cond: u8,
        value: i32,
    },
    /// Combined load-immediate + unconditional jump.
    LoadImmJump { dst: u8, value: i32, offset: i32 },
    /// Combined load-immediate + indirect jump.
    LoadImmJumpInd { base: u8, dst: u8, value: i32 },
    /// Load from absolute address (no base register).
    LoadAbsolute {
        width: MemWidth,
        dst: u8,
        address: i32,
    },
    /// Store to absolute address (no base register).
    StoreAbsolute {
        width: MemWidth,
        src: u8,
        address: i32,
    },
    /// Store immediate to absolute address.
    StoreImm {
        width: MemWidth,
        address: i32,
        value: i32,
    },
    /// Store immediate to [base + offset].
    StoreImmInd {
        width: MemWidth,
        base: u8,
        offset: i32,
        value: i32,
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

            // Conditional moves (three-register)
            Instruction::CmovIz { dst, src, cond } => Self::CmovReg {
                is_zero: true,
                dst: *dst,
                src: *src,
                cond: *cond,
            },
            Instruction::CmovNz { dst, src, cond } => Self::CmovReg {
                is_zero: false,
                dst: *dst,
                src: *src,
                cond: *cond,
            },

            // Upper multiply
            Instruction::MulUpperSS { dst, src1, src2 } => Self::BinReg {
                op: BinOp::MulUpperSS,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::MulUpperUU { dst, src1, src2 } => Self::BinReg {
                op: BinOp::MulUpperUU,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::MulUpperSU { dst, src1, src2 } => Self::BinReg {
                op: BinOp::MulUpperSU,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },

            // Rotate (three-register)
            Instruction::RotL64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RotL,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RotL32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RotL,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RotR64 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RotR,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::RotR32 { dst, src1, src2 } => Self::BinReg {
                op: BinOp::RotR,
                width: BitWidth::W32,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },

            // Inverted bitwise
            Instruction::AndInv { dst, src1, src2 } => Self::BinReg {
                op: BinOp::AndInv,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::OrInv { dst, src1, src2 } => Self::BinReg {
                op: BinOp::OrInv,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Xnor { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Xnor,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },

            // Min/Max
            Instruction::Max { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Max,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::MaxU { dst, src1, src2 } => Self::BinReg {
                op: BinOp::MaxU,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::Min { dst, src1, src2 } => Self::BinReg {
                op: BinOp::Min,
                width: BitWidth::W64,
                dst: *dst,
                src1: *src1,
                src2: *src2,
            },
            Instruction::MinU { dst, src1, src2 } => Self::BinReg {
                op: BinOp::MinU,
                width: BitWidth::W64,
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
            Instruction::AndImm { dst, src, value } => Self::BinImm {
                op: BinOp::And,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::XorImm { dst, src, value } => Self::BinImm {
                op: BinOp::Xor,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::OrImm { dst, src, value } => Self::BinImm {
                op: BinOp::Or,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::MulImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::Mul,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::MulImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::Mul,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloLImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::Shl,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloRImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::ShrU,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SharRImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::ShrS,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloLImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::Shl,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloRImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::ShrU,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SharRImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::ShrS,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::NegAddImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::NegAdd,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::NegAddImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::NegAdd,
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
            Instruction::SetGtUImm { dst, src, value } => Self::BinImm {
                op: BinOp::GtU,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SetGtSImm { dst, src, value } => Self::BinImm {
                op: BinOp::GtS,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::RotRImm32 { dst, src, value } => Self::BinImm {
                op: BinOp::RotR,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::RotRImm64 { dst, src, value } => Self::BinImm {
                op: BinOp::RotR,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },

            // Reversed-operand immediates: dst = value OP src
            Instruction::ShloLImmAlt32 { dst, src, value } => Self::BinImmRev {
                op: BinOp::Shl,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloRImmAlt32 { dst, src, value } => Self::BinImmRev {
                op: BinOp::ShrU,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SharRImmAlt32 { dst, src, value } => Self::BinImmRev {
                op: BinOp::ShrS,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloLImmAlt64 { dst, src, value } => Self::BinImmRev {
                op: BinOp::Shl,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::ShloRImmAlt64 { dst, src, value } => Self::BinImmRev {
                op: BinOp::ShrU,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::SharRImmAlt64 { dst, src, value } => Self::BinImmRev {
                op: BinOp::ShrS,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::RotRImmAlt32 { dst, src, value } => Self::BinImmRev {
                op: BinOp::RotR,
                width: BitWidth::W32,
                dst: *dst,
                src: *src,
                value: *value,
            },
            Instruction::RotRImmAlt64 { dst, src, value } => Self::BinImmRev {
                op: BinOp::RotR,
                width: BitWidth::W64,
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
            Instruction::ReverseBytes { dst, src } => Self::Unary {
                op: UnaryOp::Bswap,
                dst: *dst,
                src: *src,
            },

            // Conditional move with immediate
            Instruction::CmovIzImm { dst, cond, value } => Self::CmovImm {
                is_zero: true,
                dst: *dst,
                cond: *cond,
                value: *value,
            },
            Instruction::CmovNzImm { dst, cond, value } => Self::CmovImm {
                is_zero: false,
                dst: *dst,
                cond: *cond,
                value: *value,
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
            Instruction::LoadIndI32 { dst, base, offset } => Self::Load {
                width: MemWidth::I32,
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

            // Absolute loads (no base register)
            Instruction::LoadU8 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::U8,
                dst: *dst,
                address: *address,
            },
            Instruction::LoadI8 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::I8,
                dst: *dst,
                address: *address,
            },
            Instruction::LoadU16 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::U16,
                dst: *dst,
                address: *address,
            },
            Instruction::LoadI16 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::I16,
                dst: *dst,
                address: *address,
            },
            Instruction::LoadU32 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::U32,
                dst: *dst,
                address: *address,
            },
            Instruction::LoadI32 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::I32,
                dst: *dst,
                address: *address,
            },
            Instruction::LoadU64 { dst, address } => Self::LoadAbsolute {
                width: MemWidth::U64,
                dst: *dst,
                address: *address,
            },

            // Absolute stores (no base register)
            Instruction::StoreU8 { src, address } => Self::StoreAbsolute {
                width: MemWidth::U8,
                src: *src,
                address: *address,
            },
            Instruction::StoreU16 { src, address } => Self::StoreAbsolute {
                width: MemWidth::U16,
                src: *src,
                address: *address,
            },
            Instruction::StoreU32 { src, address } => Self::StoreAbsolute {
                width: MemWidth::U32,
                src: *src,
                address: *address,
            },
            Instruction::StoreU64 { src, address } => Self::StoreAbsolute {
                width: MemWidth::U64,
                src: *src,
                address: *address,
            },

            // Store immediate to absolute address
            Instruction::StoreImmU8 { address, value } => Self::StoreImm {
                width: MemWidth::U8,
                address: *address,
                value: *value,
            },
            Instruction::StoreImmU16 { address, value } => Self::StoreImm {
                width: MemWidth::U16,
                address: *address,
                value: *value,
            },
            Instruction::StoreImmU32 { address, value } => Self::StoreImm {
                width: MemWidth::U32,
                address: *address,
                value: *value,
            },
            Instruction::StoreImmU64 { address, value } => Self::StoreImm {
                width: MemWidth::U64,
                address: *address,
                value: *value,
            },

            // Store immediate to [base + offset]
            Instruction::StoreImmIndU8 {
                base,
                offset,
                value,
            } => Self::StoreImmInd {
                width: MemWidth::U8,
                base: *base,
                offset: *offset,
                value: *value,
            },
            Instruction::StoreImmIndU16 {
                base,
                offset,
                value,
            } => Self::StoreImmInd {
                width: MemWidth::U16,
                base: *base,
                offset: *offset,
                value: *value,
            },
            Instruction::StoreImmIndU32 {
                base,
                offset,
                value,
            } => Self::StoreImmInd {
                width: MemWidth::U32,
                base: *base,
                offset: *offset,
                value: *value,
            },
            Instruction::StoreImmIndU64 {
                base,
                offset,
                value,
            } => Self::StoreImmInd {
                width: MemWidth::U64,
                base: *base,
                offset: *offset,
                value: *value,
            },

            // Jumps
            Instruction::Jump { offset } => Self::Jump { offset: *offset },
            Instruction::JumpInd { reg, .. } => Self::JumpInd { reg: *reg },
            Instruction::LoadImmJump { reg, value, offset } => Self::LoadImmJump {
                dst: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::LoadImmJumpInd {
                base, dst, value, ..
            } => Self::LoadImmJumpInd {
                base: *base,
                dst: *dst,
                value: *value,
            },

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
            Instruction::BranchLtUImm { reg, value, offset } => Self::BranchImm {
                cond: "<u",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchLeUImm { reg, value, offset } => Self::BranchImm {
                cond: "<=u",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchGeUImm { reg, value, offset } => Self::BranchImm {
                cond: ">=u",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchGtUImm { reg, value, offset } => Self::BranchImm {
                cond: ">u",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchLtSImm { reg, value, offset } => Self::BranchImm {
                cond: "<s",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchLeSImm { reg, value, offset } => Self::BranchImm {
                cond: "<=s",
                reg: *reg,
                value: *value,
                offset: *offset,
            },
            Instruction::BranchGtSImm { reg, value, offset } => Self::BranchImm {
                cond: ">s",
                reg: *reg,
                value: *value,
                offset: *offset,
            },

            // Move register
            Instruction::MoveReg { dst, src } => Self::BinImm {
                op: BinOp::Add,
                width: BitWidth::W64,
                dst: *dst,
                src: *src,
                value: 0,
            },

            // Branch with two registers.
            // PVM convention: BranchOp { reg1: a, reg2: b } branches when b op a.
            // Swap operands so the shape reads naturally as "reg1 op reg2".
            Instruction::BranchEq { reg1, reg2, offset } => Self::BranchReg {
                cond: "==",
                reg1: *reg2,
                reg2: *reg1,
                offset: *offset,
            },
            Instruction::BranchNe { reg1, reg2, offset } => Self::BranchReg {
                cond: "!=",
                reg1: *reg2,
                reg2: *reg1,
                offset: *offset,
            },
            Instruction::BranchGeU { reg1, reg2, offset } => Self::BranchReg {
                cond: ">=u",
                reg1: *reg2,
                reg2: *reg1,
                offset: *offset,
            },
            Instruction::BranchLtU { reg1, reg2, offset } => Self::BranchReg {
                cond: "<u",
                reg1: *reg2,
                reg2: *reg1,
                offset: *offset,
            },
            Instruction::BranchLtS { reg1, reg2, offset } => Self::BranchReg {
                cond: "<s",
                reg1: *reg2,
                reg2: *reg1,
                offset: *offset,
            },
            Instruction::BranchGeS { reg1, reg2, offset } => Self::BranchReg {
                cond: ">=s",
                reg1: *reg2,
                reg2: *reg1,
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
            | Self::BinImmRev { dst, .. }
            | Self::Unary { dst, .. }
            | Self::Load { dst, .. }
            | Self::LoadAbsolute { dst, .. }
            | Self::CmovReg { dst, .. }
            | Self::CmovImm { dst, .. }
            | Self::LoadImmJump { dst, .. }
            | Self::LoadImmJumpInd { dst, .. } => Some(*dst),
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
            Self::BinImm { dst, src, .. } | Self::BinImmRev { dst, src, .. } => {
                (vec![*dst], vec![*src])
            }
            Self::Unary { dst, src, .. } => (vec![*dst], vec![*src]),
            Self::Load { dst, base, .. } => (vec![*dst], vec![*base]),
            Self::Store { base, src, .. } => (vec![], vec![*base, *src]),
            Self::LoadAbsolute { dst, .. } => (vec![*dst], vec![]),
            Self::StoreAbsolute { src, .. } => (vec![], vec![*src]),
            Self::StoreImm { .. } => (vec![], vec![]),
            Self::StoreImmInd { base, .. } => (vec![], vec![*base]),
            Self::CmovReg { dst, src, cond, .. } => (vec![*dst], vec![*src, *cond]),
            Self::CmovImm { dst, cond, .. } => (vec![*dst], vec![*cond]),
            Self::Jump { .. } => (vec![], vec![]),
            Self::JumpInd { reg, .. } => (vec![], vec![*reg]),
            Self::LoadImmJump { dst, .. } => (vec![*dst], vec![]),
            Self::LoadImmJumpInd { base, dst, .. } => (vec![*dst], vec![*base]),
            Self::BranchImm { reg, .. } => (vec![], vec![*reg]),
            Self::BranchReg { reg1, reg2, .. } => (vec![], vec![*reg1, *reg2]),
            Self::Ecalli { .. } | Self::Unknown { .. } => {
                // Conservatively assume all registers are both read and written.
                let all_regs: Vec<u8> = (0..=12).collect();
                (all_regs.clone(), all_regs)
            }
        }
    }

    /// Whether this instruction is a block terminator (ends a basic block).
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Self::Jump { .. }
                | Self::JumpInd { .. }
                | Self::LoadImmJump { .. }
                | Self::LoadImmJumpInd { .. }
                | Self::BranchImm { .. }
                | Self::BranchReg { .. }
                | Self::NoOp { name: "trap" }
        )
    }

    /// Get the jump/branch offset, if this is a control-flow instruction with a static target.
    pub fn branch_offset(&self) -> Option<i32> {
        match self {
            Self::Jump { offset } | Self::LoadImmJump { offset, .. } => Some(*offset),
            Self::BranchImm { offset, .. } => Some(*offset),
            Self::BranchReg { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    /// Whether this instruction is a conditional branch (has both target and fallthrough).
    pub fn is_conditional_branch(&self) -> bool {
        matches!(self, Self::BranchImm { .. } | Self::BranchReg { .. })
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
            Self::BinImmRev {
                op,
                width,
                dst,
                src,
                value,
            } => {
                let suffix = if *width == BitWidth::W64 { "64" } else { "" };
                format!("r{} = {} {}{} r{}", dst, value, op, suffix, src)
            }
            Self::CmovReg {
                is_zero,
                dst,
                src,
                cond,
            } => {
                let cmp = if *is_zero { "== 0" } else { "!= 0" };
                format!("if (r{} {}) r{} = r{}", cond, cmp, dst, src)
            }
            Self::CmovImm {
                is_zero,
                dst,
                cond,
                value,
            } => {
                let cmp = if *is_zero { "== 0" } else { "!= 0" };
                format!("if (r{} {}) r{} = {}", cond, cmp, dst, value)
            }
            Self::LoadImmJump { dst, value, offset } => {
                format!("r{} = {}; jump {}", dst, value, offset)
            }
            Self::LoadImmJumpInd { base, dst, value } => {
                format!("r{} = {}; jump_ind r{}", dst, value, base)
            }
            Self::LoadAbsolute {
                width,
                dst,
                address,
            } => format!("r{} = {}[{:#x}]", dst, width, address),
            Self::StoreAbsolute {
                width,
                src,
                address,
            } => format!("{}[{:#x}] = r{}", width, address, src),
            Self::StoreImm {
                width,
                address,
                value,
            } => format!("{}[{:#x}] = {}", width, address, value),
            Self::StoreImmInd {
                width,
                base,
                offset,
                value,
            } => format!("{}[r{} + {}] = {}", width, base, offset, value),
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

    #[test]
    fn test_is_terminator() {
        assert!(InstructionShape::Jump { offset: 10 }.is_terminator());
        assert!(InstructionShape::JumpInd { reg: 0 }.is_terminator());
        assert!(InstructionShape::NoOp { name: "trap" }.is_terminator());
        assert!(
            InstructionShape::BranchImm {
                cond: "==",
                reg: 0,
                value: 0,
                offset: 5,
            }
            .is_terminator()
        );
        assert!(
            InstructionShape::BranchReg {
                cond: "<u",
                reg1: 0,
                reg2: 1,
                offset: 5,
            }
            .is_terminator()
        );

        // Non-terminators
        assert!(
            !InstructionShape::NoOp {
                name: "fallthrough"
            }
            .is_terminator()
        );
        assert!(!InstructionShape::LoadImm { dst: 0, value: 42 }.is_terminator());
        assert!(!InstructionShape::Unknown { opcode: 0xFF }.is_terminator());
    }

    #[test]
    fn test_branch_offset() {
        assert_eq!(
            InstructionShape::Jump { offset: 10 }.branch_offset(),
            Some(10)
        );
        assert_eq!(
            InstructionShape::BranchImm {
                cond: "==",
                reg: 0,
                value: 0,
                offset: -5,
            }
            .branch_offset(),
            Some(-5)
        );
        assert_eq!(InstructionShape::JumpInd { reg: 0 }.branch_offset(), None);
        assert_eq!(
            InstructionShape::NoOp { name: "trap" }.branch_offset(),
            None
        );
    }

    #[test]
    fn test_is_conditional_branch() {
        assert!(
            InstructionShape::BranchImm {
                cond: "==",
                reg: 0,
                value: 0,
                offset: 5,
            }
            .is_conditional_branch()
        );
        assert!(!InstructionShape::Jump { offset: 5 }.is_conditional_branch());
        assert!(!InstructionShape::JumpInd { reg: 0 }.is_conditional_branch());
    }

    #[test]
    fn test_classify_load_store() {
        let load = Instruction::LoadIndU32 {
            dst: 1,
            base: 2,
            offset: 8,
        };
        let shape = InstructionShape::classify(&load);
        assert_eq!(shape.format_raw(), "r1 = u32[r2 + 8]");
        assert_eq!(shape.def_reg(), Some(1));

        let store = Instruction::StoreIndU64 {
            base: 3,
            src: 4,
            offset: 0,
        };
        let shape = InstructionShape::classify(&store);
        assert_eq!(shape.format_raw(), "u64[r3 + 0] = r4");
        assert_eq!(shape.def_reg(), None);
    }

    #[test]
    fn test_classify_unary() {
        let instr = Instruction::SignExtend8 { dst: 5, src: 6 };
        let shape = InstructionShape::classify(&instr);
        assert_eq!(shape.format_raw(), "r5 = sext8(r6)");
        let (defs, uses) = shape.def_use();
        assert_eq!(defs, vec![5]);
        assert_eq!(uses, vec![6]);
    }
}
