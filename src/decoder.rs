use crate::varint;
use std::error::Error;
use std::fmt;
use wasm_pvm::pvm::Instruction;

#[derive(Debug)]
pub struct DecodedProgram {
    pub jump_table: Vec<u32>,
    pub instructions: Vec<(usize, Instruction)>, // (PC, Instruction)
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum DecodeError {
    UnexpectedEof,
    InvalidOpcode(u8),
    InvalidVarInt,
    InvalidMask,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DecodeError {}

pub fn decode_blob(data: &[u8]) -> Result<DecodedProgram, Box<dyn Error>> {
    let mut cursor = Cursor::new(data);

    // 1. Decode Jump Table Length (var_u32)
    let jump_table_len = cursor.read_var_u32()?;

    // 2. Decode Item Length (u8)
    let item_len = cursor.read_u8()?;

    // 3. Decode Code Length (var_u32)
    let code_len = cursor.read_var_u32()?;

    // 4. Decode Jump Table
    let mut jump_table = Vec::with_capacity(jump_table_len as usize);
    if jump_table_len > 0 {
        if item_len != 4 {
            // In current spec, jump table entries are 4 bytes.
            // But let's follow the spec if it implies flexibility.
            // For now assume 4.
        }
        for _ in 0..jump_table_len {
            jump_table.push(cursor.read_u32()?);
        }
    }

    // 5. Read Code Section
    let code_start = cursor.position;
    if cursor.remaining() < code_len as usize {
        return Err(Box::new(DecodeError::UnexpectedEof));
    }
    let code_end = code_start + code_len as usize;
    let code_bytes = &data[code_start..code_end];
    cursor.advance(code_len as usize);

    // 6. Read Mask Section
    // The mask is the rest of the file? Or specific length?
    // In , mask is appended after code.
    // The mask has 1 bit per byte of code.
    // So mask length = ceil(code_len / 8).
    let mask_len = (code_len as usize).div_ceil(8);
    if cursor.remaining() < mask_len {
        return Err(Box::new(DecodeError::UnexpectedEof));
    }
    let mask_bytes = &data[cursor.position..cursor.position + mask_len];

    // 7. Decode Instructions using Mask
    let mut instructions = Vec::new();
    let mut pc = 0;

    while pc < code_len as usize {
        // Check if current PC is start of instruction according to mask
        let byte_idx = pc / 8;
        let bit_idx = pc % 8;
        let is_start = (mask_bytes[byte_idx] >> bit_idx) & 1 == 1;

        if !is_start {
            // This should ideally not happen if we iterate correctly instructions.
            // But if we jump or have data, maybe?
            // Actually, we should just read the instruction at PC if the mask says so.
            // If mask says no, it's padding or data?
            // Spec says "mask... marks instruction boundaries".
            // Let's trust the mask.
            pc += 1;
            continue;
        }

        // Find the length of this instruction by scanning for the next set bit in mask
        let instr_len = find_instruction_length(mask_bytes, pc, code_len as usize);

        let (instr, _) = decode_instruction(&code_bytes[pc..pc + instr_len], instr_len)?;
        instructions.push((pc, instr));
        pc += instr_len;
    }

    Ok(DecodedProgram {
        jump_table,
        instructions,
    })
}

/// Find the length of an instruction by scanning the mask for the next set bit.
/// Returns the distance from current PC to the next set bit (or end of code).
fn find_instruction_length(mask_bytes: &[u8], start_pc: usize, code_len: usize) -> usize {
    let mut pc = start_pc + 1;
    while pc < code_len {
        let byte_idx = pc / 8;
        let bit_idx = pc % 8;
        if byte_idx >= mask_bytes.len() {
            break;
        }
        let is_start = (mask_bytes[byte_idx] >> bit_idx) & 1 == 1;
        if is_start {
            return pc - start_pc;
        }
        pc += 1;
    }
    code_len - start_pc
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn advance(&mut self, n: usize) {
        self.position += n;
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        if self.position >= self.data.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let b = self.data[self.position];
        self.position += 1;
        Ok(b)
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        if self.remaining() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = &self.data[self.position..self.position + 4];
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        self.position += 4;
        Ok(val)
    }

    fn read_var_u32(&mut self) -> Result<u32, DecodeError> {
        match varint::decode_var_u32(&self.data[self.position..]) {
            Some((val, len)) => {
                self.position += len;
                Ok(val)
            }
            None => Err(DecodeError::InvalidVarInt),
        }
    }
}

/// Decode an immediate value from bytes (variable-length, little-endian).
/// The length determines how many bytes to read.
fn decode_imm_bytes(data: &[u8]) -> i32 {
    match data.len() {
        0 => 0,
        1 => data[0] as i8 as i32,
        2 => i16::from_le_bytes([data[0], data[1]]) as i32,
        3 => {
            let mut bytes = [0u8; 4];
            bytes[..3].copy_from_slice(&data[..3]);
            // Sign-extend from 24 bits
            let val = i32::from_le_bytes(bytes);
            if val & 0x0080_0000 != 0 {
                val | (-1i32 ^ 0x00FF_FFFF)
            } else {
                val & 0x00FF_FFFF
            }
        }
        _ => i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
    }
}

/// Decode an unsigned immediate value from bytes (variable-length, little-endian).
fn decode_uimm_bytes(data: &[u8]) -> u32 {
    match data.len() {
        0 => 0,
        1 => data[0] as u32,
        2 => u16::from_le_bytes([data[0], data[1]]) as u32,
        3 => {
            let mut bytes = [0u8; 4];
            bytes[..3].copy_from_slice(&data[..3]);
            u32::from_le_bytes(bytes) & 0x00FF_FFFF
        }
        _ => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
    }
}

fn decode_instruction(data: &[u8], length: usize) -> Result<(Instruction, usize), DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    let opcode_u8 = data[0];

    match opcode_u8 {
        // Zero-operand instructions
        0 => Ok((Instruction::Trap, length)),
        1 => Ok((Instruction::Fallthrough, length)),

        // LoadImm64: opcode + reg + 8-byte value
        20 => {
            if length < 10 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg = data[1] & 0x0F;
            let val = u64::from_le_bytes(data[2..10].try_into().unwrap());
            Ok((Instruction::LoadImm64 { reg, value: val }, length))
        }

        // LoadImm: opcode + reg + variable-length immediate
        51 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg = data[1] & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadImm { reg, value }, length))
        }

        // Jump: opcode + 4-byte offset
        40 => {
            if length < 5 {
                return Err(DecodeError::UnexpectedEof);
            }
            let offset = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Ok((Instruction::Jump { offset }, length))
        }

        // JumpInd: opcode + reg + variable-length offset
        50 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg = data[1] & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::JumpInd { reg, offset }, length))
        }

        // Three-register instructions: opcode + (src2_hi | src1_lo) + dst
        190 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Add32 { dst, src1, src2 }, length))
        }
        191 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Sub32 { dst, src1, src2 }, length))
        }
        192 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Mul32 { dst, src1, src2 }, length))
        }
        193 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::DivU32 { dst, src1, src2 }, length))
        }
        194 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::DivS32 { dst, src1, src2 }, length))
        }
        195 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::RemU32 { dst, src1, src2 }, length))
        }
        196 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::RemS32 { dst, src1, src2 }, length))
        }
        197 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::ShloL32 { dst, src1, src2 }, length))
        }
        198 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::ShloR32 { dst, src1, src2 }, length))
        }
        199 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::SharR32 { dst, src1, src2 }, length))
        }
        200 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Add64 { dst, src1, src2 }, length))
        }
        201 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Sub64 { dst, src1, src2 }, length))
        }
        202 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Mul64 { dst, src1, src2 }, length))
        }
        203 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::DivU64 { dst, src1, src2 }, length))
        }
        204 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::DivS64 { dst, src1, src2 }, length))
        }
        205 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::RemU64 { dst, src1, src2 }, length))
        }
        206 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::RemS64 { dst, src1, src2 }, length))
        }
        207 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::ShloL64 { dst, src1, src2 }, length))
        }
        208 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::ShloR64 { dst, src1, src2 }, length))
        }
        209 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::SharR64 { dst, src1, src2 }, length))
        }
        210 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::And { dst, src1, src2 }, length))
        }
        211 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Xor { dst, src1, src2 }, length))
        }
        212 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::Or { dst, src1, src2 }, length))
        }
        216 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::SetLtU { dst, src1, src2 }, length))
        }
        217 => {
            if length < 3 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src1 = data[1] & 0x0F;
            let src2 = (data[1] >> 4) & 0x0F;
            let dst = data[2] & 0x0F;
            Ok((Instruction::SetLtS { dst, src1, src2 }, length))
        }

        // Two-register instructions: opcode + (src_hi | dst_lo)
        101 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::Sbrk { dst, src }, length))
        }
        102 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::CountSetBits64 { dst, src }, length))
        }
        103 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::CountSetBits32 { dst, src }, length))
        }
        104 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::LeadingZeroBits64 { dst, src }, length))
        }
        105 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::LeadingZeroBits32 { dst, src }, length))
        }
        106 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::TrailingZeroBits64 { dst, src }, length))
        }
        107 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::TrailingZeroBits32 { dst, src }, length))
        }
        108 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::SignExtend8 { dst, src }, length))
        }
        109 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::SignExtend16 { dst, src }, length))
        }
        110 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            Ok((Instruction::ZeroExtend16 { dst, src }, length))
        }

        // AddImm32: opcode + (src_hi | dst_lo) + variable-length immediate
        131 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            Ok((Instruction::AddImm32 { dst, src, value }, length))
        }

        // AddImm64: opcode + (src_hi | dst_lo) + variable-length immediate
        149 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            Ok((Instruction::AddImm64 { dst, src, value }, length))
        }

        // SetLtUImm: opcode + (src_hi | dst_lo) + variable-length immediate
        136 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            Ok((Instruction::SetLtUImm { dst, src, value }, length))
        }

        // SetLtSImm: opcode + (src_hi | dst_lo) + variable-length immediate
        137 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let src = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            Ok((Instruction::SetLtSImm { dst, src, value }, length))
        }

        // LoadIndU8: opcode + (base_hi | dst_lo) + variable-length offset
        124 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadIndU8 { dst, base, offset }, length))
        }

        // LoadIndI8: opcode + (base_hi | dst_lo) + variable-length offset
        125 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadIndI8 { dst, base, offset }, length))
        }

        // StoreIndU8: opcode + (base_hi | src_lo) + variable-length offset
        120 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::StoreIndU8 { base, src, offset }, length))
        }

        // LoadIndU16: opcode + (base_hi | dst_lo) + variable-length offset
        126 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadIndU16 { dst, base, offset }, length))
        }

        // LoadIndI16: opcode + (base_hi | dst_lo) + variable-length offset
        127 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadIndI16 { dst, base, offset }, length))
        }

        // StoreIndU16: opcode + (base_hi | src_lo) + variable-length offset
        121 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::StoreIndU16 { base, src, offset }, length))
        }

        // LoadIndU32: opcode + (base_hi | dst_lo) + variable-length offset
        128 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadIndU32 { dst, base, offset }, length))
        }

        // StoreIndU32: opcode + (base_hi | src_lo) + variable-length offset
        122 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::StoreIndU32 { base, src, offset }, length))
        }

        // LoadIndU64: opcode + (base_hi | dst_lo) + variable-length offset
        130 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let dst = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::LoadIndU64 { dst, base, offset }, length))
        }

        // StoreIndU64: opcode + (base_hi | src_lo) + variable-length offset
        123 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let src = data[1] & 0x0F;
            let base = (data[1] >> 4) & 0x0F;
            let imm_len = length - 2;
            let imm_bytes = &data[2..2 + imm_len];
            let offset = decode_imm_bytes(imm_bytes);
            Ok((Instruction::StoreIndU64 { base, src, offset }, length))
        }

        // BranchEqImm: opcode + (imm_len_hi | reg_lo) + variable-length imm + 4-byte offset
        81 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg = data[1] & 0x0F;
            let imm_len = ((data[1] >> 4) & 0x0F) as usize;
            if length < 2 + imm_len + 4 {
                return Err(DecodeError::UnexpectedEof);
            }
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            let offset_start = 2 + imm_len;
            let offset = i32::from_le_bytes([
                data[offset_start],
                data[offset_start + 1],
                data[offset_start + 2],
                data[offset_start + 3],
            ]);
            Ok((Instruction::BranchEqImm { reg, value, offset }, length))
        }

        // BranchNeImm: opcode + (imm_len_hi | reg_lo) + variable-length imm + 4-byte offset
        82 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg = data[1] & 0x0F;
            let imm_len = ((data[1] >> 4) & 0x0F) as usize;
            if length < 2 + imm_len + 4 {
                return Err(DecodeError::UnexpectedEof);
            }
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            let offset_start = 2 + imm_len;
            let offset = i32::from_le_bytes([
                data[offset_start],
                data[offset_start + 1],
                data[offset_start + 2],
                data[offset_start + 3],
            ]);
            Ok((Instruction::BranchNeImm { reg, value, offset }, length))
        }

        // BranchGeSImm: opcode + (imm_len_hi | reg_lo) + variable-length imm + 4-byte offset
        89 => {
            if length < 2 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg = data[1] & 0x0F;
            let imm_len = ((data[1] >> 4) & 0x0F) as usize;
            if length < 2 + imm_len + 4 {
                return Err(DecodeError::UnexpectedEof);
            }
            let imm_bytes = &data[2..2 + imm_len];
            let value = decode_imm_bytes(imm_bytes);
            let offset_start = 2 + imm_len;
            let offset = i32::from_le_bytes([
                data[offset_start],
                data[offset_start + 1],
                data[offset_start + 2],
                data[offset_start + 3],
            ]);
            Ok((Instruction::BranchGeSImm { reg, value, offset }, length))
        }

        // BranchGeU: opcode + (reg1_hi | reg2_lo) + 4-byte offset
        174 => {
            if length < 6 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg2 = data[1] & 0x0F;
            let reg1 = (data[1] >> 4) & 0x0F;
            let offset = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
            Ok((Instruction::BranchGeU { reg1, reg2, offset }, length))
        }

        // BranchLtU: opcode + (reg1_hi | reg2_lo) + 4-byte offset
        172 => {
            if length < 6 {
                return Err(DecodeError::UnexpectedEof);
            }
            let reg2 = data[1] & 0x0F;
            let reg1 = (data[1] >> 4) & 0x0F;
            let offset = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
            Ok((Instruction::BranchLtU { reg1, reg2, offset }, length))
        }

        // Ecalli: opcode + variable-length unsigned immediate
        10 => {
            if length < 1 {
                return Err(DecodeError::UnexpectedEof);
            }
            let imm_len = length - 1;
            let imm_bytes = &data[1..1 + imm_len];
            let index = decode_uimm_bytes(imm_bytes);
            Ok((Instruction::Ecalli { index }, length))
        }

        _ => Err(DecodeError::InvalidOpcode(opcode_u8)),
    }
}
