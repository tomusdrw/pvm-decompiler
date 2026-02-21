//! Binary Format Decoding
//!
//! Parses PVM bytecode from two formats:
//! - **SPI format**: Header with code/data section offsets and jump table
//! - **Raw ProgramBlob**: Bare code section with bitmask for instruction boundaries
//!
//! Both paths produce a `DecodedProgram` containing the instruction stream,
//! jump table entries, and code length for downstream CFG construction.

use crate::varint;
use std::error::Error;
use std::fmt;
use wasm_pvm::pvm::Instruction;

#[derive(Debug)]
pub struct DecodedProgram {
    pub jump_table: Vec<u32>,
    pub instructions: Vec<(usize, Instruction)>, // (PC, Instruction)
    pub code_len: usize,                         // Total byte length of the code section
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum DecodeError {
    UnexpectedEof,
    InvalidOpcode(u8),
    InvalidVarInt,
    InvalidMask,
    UnsupportedJumpTableEntrySize(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DecodeError {}

/// Try to strip metadata prefix from PVM blob.
/// Format: <var-len-encoded-metadata-length><metadata-bytes><spi-program>
///
/// Returns the blob data (with metadata stripped if present).
/// Uses a heuristic: if the first varint is small and the following bytes
/// are mostly printable ASCII, treat it as metadata and skip it.
fn try_strip_metadata(data: &[u8]) -> Result<&[u8], Box<dyn Error>> {
    if data.is_empty() {
        return Ok(data);
    }

    // Try to read the first varint
    match varint::decode_var_u32(data) {
        Some((metadata_len, varint_len)) => {
            let metadata_len = metadata_len as usize;

            // Check if this could be metadata:
            // 1. metadata_len must be reasonable (> 0 and < file size)
            // 2. The bytes after metadata should be enough for a valid blob
            // 3. The metadata bytes should be mostly printable ASCII

            if metadata_len == 0 {
                // No metadata, return as-is
                return Ok(data);
            }

            let metadata_start = varint_len;
            let metadata_end = metadata_start + metadata_len;

            // Check bounds
            if metadata_end > data.len() {
                // Not enough data for metadata, assume no metadata
                return Ok(data);
            }

            // Check if metadata bytes are mostly printable ASCII
            let metadata_bytes = &data[metadata_start..metadata_end];
            let printable_count = metadata_bytes
                .iter()
                .filter(|&&b| (32..=126).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
                .count();

            // If at least 80% of bytes are printable, treat as metadata
            if printable_count as f64 / metadata_bytes.len() as f64 >= 0.8 {
                // This looks like metadata, skip it
                return Ok(&data[metadata_end..]);
            }
        }
        None => {
            // Invalid varint, assume no metadata
        }
    }

    // No metadata detected, return original data
    Ok(data)
}

/// Decode SPI format: metadata + SPI header + ro_data + rw_data + code_blob
/// Format:
/// [varint: metadata_len]
/// [metadata_bytes]
/// [u24: ro_data_len]
/// [u24: rw_data_len]
/// [u16: heap_pages]
/// [u24: stack_size]
/// [ro_data: ro_data_len bytes]
/// [rw_data: rw_data_len bytes]
/// [u32: code_blob_len]
/// [code_blob: code_blob_len bytes] ← This is the ProgramBlob!
pub fn decode_spi(data: &[u8]) -> Result<DecodedProgram, Box<dyn Error>> {
    // Try to strip metadata prefix if present
    let blob_data = try_strip_metadata(data)?;

    let mut cursor = Cursor::new(blob_data);

    // Parse SPI header
    // 1. ro_data_len (u24 = 3 bytes LE)
    let ro_data_len = cursor.read_u24()?;

    // 2. rw_data_len (u24 = 3 bytes LE)
    let rw_data_len = cursor.read_u24()?;

    // 3. heap_pages (u16 = 2 bytes LE)
    let _heap_pages = cursor.read_u16()?;

    // 4. stack_size (u24 = 3 bytes LE)
    let _stack_size = cursor.read_u24()?;

    // 5. Skip ro_data section
    cursor.advance(ro_data_len as usize);

    // 6. Skip rw_data section
    cursor.advance(rw_data_len as usize);

    // 7. Read code_blob_len (u32 LE)
    let code_blob_len = cursor.read_u32()?;

    // 8. Extract code_blob bytes
    if cursor.remaining() < code_blob_len as usize {
        return Err(Box::new(DecodeError::UnexpectedEof));
    }

    let code_blob_start = cursor.position;
    let code_blob_end = code_blob_start + code_blob_len as usize;
    let code_blob = &blob_data[code_blob_start..code_blob_end];

    // 9. Decode the code_blob as a ProgramBlob
    decode_blob_internal(code_blob)
}

pub fn decode_blob(data: &[u8]) -> Result<DecodedProgram, Box<dyn Error>> {
    // Try to strip metadata prefix if present
    let blob_data = try_strip_metadata(data)?;

    decode_blob_internal(blob_data)
}

fn decode_blob_internal(blob_data: &[u8]) -> Result<DecodedProgram, Box<dyn Error>> {
    let mut cursor = Cursor::new(blob_data);

    // 1. Decode Jump Table Length (var_u32)
    let jump_table_len = cursor.read_var_u32()?;

    // 2. Decode Item Length (u8)
    let item_len = cursor.read_u8()?;

    // 3. Decode Code Length (var_u32)
    let code_len = cursor.read_var_u32()?;

    // 4. Decode Jump Table
    let mut jump_table = Vec::with_capacity(jump_table_len as usize);
    if item_len > 0 && jump_table_len > 0 {
        for _i in 0..jump_table_len {
            let entry = cursor.read_n_byte_le(item_len)?;
            jump_table.push(entry);
        }
    }

    // 5. Read Code Section
    let code_start = cursor.position;
    if cursor.remaining() < code_len as usize {
        return Err(Box::new(DecodeError::UnexpectedEof));
    }
    let code_end = code_start + code_len as usize;
    let code_bytes = &blob_data[code_start..code_end];
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
    let mask_bytes = &blob_data[cursor.position..cursor.position + mask_len];

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
        code_len: code_len as usize,
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

    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        if self.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = &self.data[self.position..self.position + 2];
        let val = u16::from_le_bytes(bytes.try_into().unwrap());
        self.position += 2;
        Ok(val)
    }

    fn read_u24(&mut self) -> Result<u32, DecodeError> {
        if self.remaining() < 3 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = &self.data[self.position..self.position + 3];
        // u24 is stored as 3 bytes LE, interpret as u32
        let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
        self.position += 3;
        Ok(val)
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

    /// Read an N-byte little-endian unsigned integer (1, 2, 3, or 4 bytes).
    fn read_n_byte_le(&mut self, n: u8) -> Result<u32, DecodeError> {
        let n = n as usize;
        if n == 0 || n > 4 {
            return Err(DecodeError::UnsupportedJumpTableEntrySize(n as u8));
        }
        if self.remaining() < n {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = &self.data[self.position..self.position + n];
        let mut buf = [0u8; 4];
        buf[..n].copy_from_slice(bytes);
        self.position += n;
        Ok(u32::from_le_bytes(buf))
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

/// Three-register: opcode + (src2_hi | src1_lo) + dst
macro_rules! decode_three_reg {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 3 {
            return Err(DecodeError::UnexpectedEof);
        }
        let src1 = $data[1] & 0x0F;
        let src2 = ($data[1] >> 4) & 0x0F;
        let dst = $data[2] & 0x0F;
        Ok((Instruction::$variant { dst, src1, src2 }, $length))
    }};
}

/// Two-register: opcode + (src_hi | dst_lo)
macro_rules! decode_two_reg {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let dst = $data[1] & 0x0F;
        let src = ($data[1] >> 4) & 0x0F;
        Ok((Instruction::$variant { dst, src }, $length))
    }};
}

/// Two-register + variable-length signed immediate: opcode + (src_hi | dst_lo) + imm
macro_rules! decode_two_reg_imm {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let dst = $data[1] & 0x0F;
        let src = ($data[1] >> 4) & 0x0F;
        let value = decode_imm_bytes(&$data[2..$length]);
        Ok((Instruction::$variant { dst, src, value }, $length))
    }};
}

/// Load indirect: opcode + (base_hi | dst_lo) + variable-length offset
macro_rules! decode_load_ind {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let dst = $data[1] & 0x0F;
        let base = ($data[1] >> 4) & 0x0F;
        let offset = decode_imm_bytes(&$data[2..$length]);
        Ok((Instruction::$variant { dst, base, offset }, $length))
    }};
}

/// Store indirect: opcode + (base_hi | src_lo) + variable-length offset
macro_rules! decode_store_ind {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let src = $data[1] & 0x0F;
        let base = ($data[1] >> 4) & 0x0F;
        let offset = decode_imm_bytes(&$data[2..$length]);
        Ok((Instruction::$variant { base, src, offset }, $length))
    }};
}

/// Branch with immediate: opcode + (imm_len_hi | reg_lo) + variable-length imm + 4-byte offset
macro_rules! decode_branch_imm {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let reg = $data[1] & 0x0F;
        let imm_len = (($data[1] >> 4) & 0x0F) as usize;
        if $length < 2 + imm_len + 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = decode_imm_bytes(&$data[2..2 + imm_len]);
        let os = 2 + imm_len;
        let offset = i32::from_le_bytes([$data[os], $data[os + 1], $data[os + 2], $data[os + 3]]);
        Ok((Instruction::$variant { reg, value, offset }, $length))
    }};
}

/// Branch with two registers: opcode + (reg1_hi | reg2_lo) + 4-byte offset
macro_rules! decode_branch_reg {
    ($data:expr, $length:expr, $variant:ident) => {{
        if $length < 6 {
            return Err(DecodeError::UnexpectedEof);
        }
        let reg2 = $data[1] & 0x0F;
        let reg1 = ($data[1] >> 4) & 0x0F;
        let offset = i32::from_le_bytes([$data[2], $data[3], $data[4], $data[5]]);
        Ok((Instruction::$variant { reg1, reg2, offset }, $length))
    }};
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
            let value = decode_imm_bytes(&data[2..length]);
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
            let offset = decode_imm_bytes(&data[2..length]);
            Ok((Instruction::JumpInd { reg, offset }, length))
        }

        // Three-register instructions
        190 => decode_three_reg!(data, length, Add32),
        191 => decode_three_reg!(data, length, Sub32),
        192 => decode_three_reg!(data, length, Mul32),
        193 => decode_three_reg!(data, length, DivU32),
        194 => decode_three_reg!(data, length, DivS32),
        195 => decode_three_reg!(data, length, RemU32),
        196 => decode_three_reg!(data, length, RemS32),
        197 => decode_three_reg!(data, length, ShloL32),
        198 => decode_three_reg!(data, length, ShloR32),
        199 => decode_three_reg!(data, length, SharR32),
        200 => decode_three_reg!(data, length, Add64),
        201 => decode_three_reg!(data, length, Sub64),
        202 => decode_three_reg!(data, length, Mul64),
        203 => decode_three_reg!(data, length, DivU64),
        204 => decode_three_reg!(data, length, DivS64),
        205 => decode_three_reg!(data, length, RemU64),
        206 => decode_three_reg!(data, length, RemS64),
        207 => decode_three_reg!(data, length, ShloL64),
        208 => decode_three_reg!(data, length, ShloR64),
        209 => decode_three_reg!(data, length, SharR64),
        210 => decode_three_reg!(data, length, And),
        211 => decode_three_reg!(data, length, Xor),
        212 => decode_three_reg!(data, length, Or),
        216 => decode_three_reg!(data, length, SetLtU),
        217 => decode_three_reg!(data, length, SetLtS),

        // Two-register instructions
        101 => decode_two_reg!(data, length, Sbrk),
        102 => decode_two_reg!(data, length, CountSetBits64),
        103 => decode_two_reg!(data, length, CountSetBits32),
        104 => decode_two_reg!(data, length, LeadingZeroBits64),
        105 => decode_two_reg!(data, length, LeadingZeroBits32),
        106 => decode_two_reg!(data, length, TrailingZeroBits64),
        107 => decode_two_reg!(data, length, TrailingZeroBits32),
        108 => decode_two_reg!(data, length, SignExtend8),
        109 => decode_two_reg!(data, length, SignExtend16),
        110 => decode_two_reg!(data, length, ZeroExtend16),

        // Two-register + immediate instructions
        131 => decode_two_reg_imm!(data, length, AddImm32),
        149 => decode_two_reg_imm!(data, length, AddImm64),
        136 => decode_two_reg_imm!(data, length, SetLtUImm),
        137 => decode_two_reg_imm!(data, length, SetLtSImm),

        // Load indirect instructions
        124 => decode_load_ind!(data, length, LoadIndU8),
        125 => decode_load_ind!(data, length, LoadIndI8),
        126 => decode_load_ind!(data, length, LoadIndU16),
        127 => decode_load_ind!(data, length, LoadIndI16),
        128 => decode_load_ind!(data, length, LoadIndU32),
        130 => decode_load_ind!(data, length, LoadIndU64),

        // Store indirect instructions
        120 => decode_store_ind!(data, length, StoreIndU8),
        121 => decode_store_ind!(data, length, StoreIndU16),
        122 => decode_store_ind!(data, length, StoreIndU32),
        123 => decode_store_ind!(data, length, StoreIndU64),

        // Branch with immediate instructions
        81 => decode_branch_imm!(data, length, BranchEqImm),
        82 => decode_branch_imm!(data, length, BranchNeImm),
        89 => decode_branch_imm!(data, length, BranchGeSImm),

        // Branch with two registers
        172 => decode_branch_reg!(data, length, BranchLtU),
        174 => decode_branch_reg!(data, length, BranchGeU),

        // Ecalli: opcode + variable-length unsigned immediate
        10 => {
            let index = decode_uimm_bytes(&data[1..length]);
            Ok((Instruction::Ecalli { index }, length))
        }

        _ => Ok((
            Instruction::Unknown {
                opcode: opcode_u8,
                raw_bytes: data[..length].to_vec(),
            },
            length,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decode_imm_bytes ---

    #[test]
    fn test_decode_imm_empty() {
        assert_eq!(decode_imm_bytes(&[]), 0);
    }

    #[test]
    fn test_decode_imm_1byte_positive() {
        assert_eq!(decode_imm_bytes(&[42]), 42);
    }

    #[test]
    fn test_decode_imm_1byte_negative() {
        // 0xFF as i8 = -1
        assert_eq!(decode_imm_bytes(&[0xFF]), -1);
        // 0x80 as i8 = -128
        assert_eq!(decode_imm_bytes(&[0x80]), -128);
    }

    #[test]
    fn test_decode_imm_2bytes() {
        // 0x0100 LE = [0x00, 0x01] = 256
        assert_eq!(decode_imm_bytes(&[0x00, 0x01]), 256);
        // 0xFFFF LE = -1 as i16
        assert_eq!(decode_imm_bytes(&[0xFF, 0xFF]), -1);
    }

    #[test]
    fn test_decode_imm_4bytes() {
        assert_eq!(decode_imm_bytes(&[0x01, 0x00, 0x00, 0x00]), 1);
        assert_eq!(decode_imm_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]), -1);
    }

    #[test]
    fn test_decode_uimm_bytes() {
        assert_eq!(decode_uimm_bytes(&[]), 0);
        assert_eq!(decode_uimm_bytes(&[42]), 42);
        assert_eq!(decode_uimm_bytes(&[0xFF]), 255);
        assert_eq!(decode_uimm_bytes(&[0x00, 0x01]), 256);
    }

    // --- decode_instruction ---

    #[test]
    fn test_decode_trap() {
        let (instr, len) = decode_instruction(&[0], 1).unwrap();
        assert!(matches!(instr, Instruction::Trap));
        assert_eq!(len, 1);
    }

    #[test]
    fn test_decode_fallthrough() {
        let (instr, len) = decode_instruction(&[1], 1).unwrap();
        assert!(matches!(instr, Instruction::Fallthrough));
        assert_eq!(len, 1);
    }

    #[test]
    fn test_decode_load_imm() {
        // Opcode 51, reg=3, value=42 (1 byte imm)
        let (instr, _) = decode_instruction(&[51, 0x03, 42], 3).unwrap();
        assert!(matches!(instr, Instruction::LoadImm { reg: 3, value: 42 }));
    }

    #[test]
    fn test_decode_load_imm_negative() {
        // Opcode 51, reg=0, value=-1 (0xFF as 1 byte)
        let (instr, _) = decode_instruction(&[51, 0x00, 0xFF], 3).unwrap();
        assert!(matches!(instr, Instruction::LoadImm { reg: 0, value: -1 }));
    }

    #[test]
    fn test_decode_add32() {
        // Opcode 190, src1=2 (low nibble), src2=3 (high nibble) -> byte1=0x32, dst=5
        let (instr, _) = decode_instruction(&[190, 0x32, 0x05], 3).unwrap();
        assert!(matches!(
            instr,
            Instruction::Add32 {
                dst: 5,
                src1: 2,
                src2: 3
            }
        ));
    }

    #[test]
    fn test_decode_jump() {
        // Opcode 40, offset=10 (LE i32)
        let (instr, _) = decode_instruction(&[40, 0x0A, 0x00, 0x00, 0x00], 5).unwrap();
        assert!(matches!(instr, Instruction::Jump { offset: 10 }));
    }

    #[test]
    fn test_decode_jump_negative_offset() {
        // Opcode 40, offset=-5 (LE i32 = FB FF FF FF)
        let bytes: [u8; 5] = [40, 0xFB, 0xFF, 0xFF, 0xFF];
        let (instr, _) = decode_instruction(&bytes, 5).unwrap();
        assert!(matches!(instr, Instruction::Jump { offset: -5 }));
    }

    #[test]
    fn test_decode_ecalli() {
        // Opcode 10, index=7 (1 byte unsigned)
        let (instr, _) = decode_instruction(&[10, 7], 2).unwrap();
        assert!(matches!(instr, Instruction::Ecalli { index: 7 }));
    }

    #[test]
    fn test_decode_unknown_opcode() {
        let (instr, len) = decode_instruction(&[255], 1).unwrap();
        assert_eq!(len, 1);
        assert!(matches!(instr, Instruction::Unknown { opcode: 255, .. }));
    }

    #[test]
    fn test_decode_branch_ne_imm() {
        // Opcode 82, reg=3, imm_len=1 -> byte1 = (1 << 4) | 3 = 0x13
        // imm = 0 (1 byte), offset = 10 (LE i32)
        let data = [82, 0x13, 0x00, 0x0A, 0x00, 0x00, 0x00];
        let (instr, _) = decode_instruction(&data, 7).unwrap();
        assert!(matches!(
            instr,
            Instruction::BranchNeImm {
                reg: 3,
                value: 0,
                offset: 10
            }
        ));
    }

    #[test]
    fn test_decode_store_load_u64() {
        // StoreIndU64: opcode 123, base=2 (high), src=1 (low) -> byte1=0x21, offset=8
        let (instr, _) = decode_instruction(&[123, 0x21, 8], 3).unwrap();
        assert!(matches!(
            instr,
            Instruction::StoreIndU64 {
                base: 2,
                src: 1,
                offset: 8
            }
        ));

        // LoadIndU64: opcode 130, base=2 (high), dst=3 (low) -> byte1=0x23, offset=8
        let (instr, _) = decode_instruction(&[130, 0x23, 8], 3).unwrap();
        assert!(matches!(
            instr,
            Instruction::LoadIndU64 {
                dst: 3,
                base: 2,
                offset: 8
            }
        ));
    }

    #[test]
    fn test_decode_two_reg() {
        // SignExtend8: opcode 108, dst=4 (low), src=7 (high) -> byte1=0x74
        let (instr, _) = decode_instruction(&[108, 0x74], 2).unwrap();
        assert!(matches!(instr, Instruction::SignExtend8 { dst: 4, src: 7 }));
    }

    #[test]
    fn test_decode_two_reg_imm() {
        // AddImm32: opcode 131, dst=2 (low), src=5 (high) -> byte1=0x52, value=10
        let (instr, _) = decode_instruction(&[131, 0x52, 10], 3).unwrap();
        assert!(matches!(
            instr,
            Instruction::AddImm32 {
                dst: 2,
                src: 5,
                value: 10
            }
        ));
    }

    #[test]
    fn test_decode_branch_reg() {
        // BranchGeU: opcode 174, reg2=1 (low), reg1=3 (high) -> byte1=0x31, offset=20
        let data = [174, 0x31, 0x14, 0x00, 0x00, 0x00];
        let (instr, _) = decode_instruction(&data, 6).unwrap();
        assert!(matches!(
            instr,
            Instruction::BranchGeU {
                reg1: 3,
                reg2: 1,
                offset: 20
            }
        ));
    }

    #[test]
    fn test_decode_three_reg_too_short() {
        // Three-register instruction with insufficient length should error
        let result = decode_instruction(&[190, 0x32], 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_branch_imm_too_short() {
        // BranchEqImm with imm_len=1 but not enough bytes for the 4-byte offset
        let result = decode_instruction(&[81, 0x13, 0x00], 3);
        assert!(result.is_err());
    }

    // --- decode_blob_internal ---

    #[test]
    fn test_decode_minimal_blob() {
        // Minimal blob: jump_table_len=0, item_len=0, code_len=1, code=[trap], mask=[0x01]
        let blob = [
            0x00, // jump_table_len = 0 (varint)
            0x00, // item_len = 0
            0x01, // code_len = 1 (varint)
            0x00, // code: opcode 0 = Trap
            0x01, // mask: bit 0 set (instruction starts at PC 0)
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert!(result.jump_table.is_empty());
        assert_eq!(result.instructions.len(), 1);
        assert!(matches!(result.instructions[0], (0, Instruction::Trap)));
    }

    #[test]
    fn test_decode_blob_two_instructions() {
        // Two instructions: Trap + Fallthrough
        let blob = [
            0x00, // jump_table_len = 0
            0x00, // item_len = 0
            0x02, // code_len = 2
            0x00, // code[0]: Trap
            0x01, // code[1]: Fallthrough
            0x03, // mask: bits 0 and 1 set (both PCs are instruction starts)
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert_eq!(result.instructions.len(), 2);
        assert!(matches!(result.instructions[0], (0, Instruction::Trap)));
        assert!(matches!(
            result.instructions[1],
            (1, Instruction::Fallthrough)
        ));
    }

    #[test]
    fn test_decode_blob_with_1byte_jump_table() {
        // jump_table_len=2, item_len=1, code_len=1, jump_table=[10, 20], code=[trap], mask
        let blob = [
            0x02, // jump_table_len = 2
            0x01, // item_len = 1
            0x01, // code_len = 1
            10,   // jump_table[0] = 10
            20,   // jump_table[1] = 20
            0x00, // code: Trap
            0x01, // mask
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert_eq!(result.jump_table, vec![10, 20]);
        assert_eq!(result.instructions.len(), 1);
    }

    #[test]
    fn test_decode_blob_with_2byte_jump_table() {
        // jump_table_len=1, item_len=2, code_len=1, jump_table=[0x0102], code=[trap], mask
        let blob = [
            0x01, // jump_table_len = 1
            0x02, // item_len = 2
            0x01, // code_len = 1
            0x02, 0x01, // jump_table[0] = 258 (LE)
            0x00, // code: Trap
            0x01, // mask
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert_eq!(result.jump_table, vec![258]);
    }

    #[test]
    fn test_decode_blob_with_3byte_jump_table() {
        let blob = [
            0x01, // jump_table_len = 1
            0x03, // item_len = 3
            0x01, // code_len = 1
            0x01, 0x02, 0x03, // jump_table[0] = 0x030201 (LE)
            0x00, // code: Trap
            0x01, // mask
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert_eq!(result.jump_table, vec![0x030201]);
    }

    #[test]
    fn test_decode_blob_with_4byte_jump_table() {
        let blob = [
            0x01, // jump_table_len = 1
            0x04, // item_len = 4
            0x01, // code_len = 1
            0x64, 0x00, 0x00, 0x00, // jump_table[0] = 100 (LE)
            0x00, // code: Trap
            0x01, // mask
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert_eq!(result.jump_table, vec![100]);
    }

    #[test]
    fn test_decode_blob_with_unsupported_entry_size() {
        // item_len=5 is not supported and should produce an error
        let blob = [
            0x01, // jump_table_len = 1
            0x05, // item_len = 5 (unsupported)
            0x01, // code_len = 1
            0x00, 0x00, 0x00, 0x00, 0x00, // 5 bytes of data
            0x00, // code: Trap
            0x01, // mask
        ];
        let result = decode_blob_internal(&blob);
        assert!(result.is_err(), "item_len=5 should be rejected");
    }

    #[test]
    fn test_decode_blob_with_unknown_instruction() {
        // Blob with: Trap, unknown opcode 0xFF, Fallthrough
        let blob = [
            0x00, // jump_table_len = 0
            0x00, // item_len = 0
            0x03, // code_len = 3
            0x00, // code[0]: Trap
            0xFF, // code[1]: unknown opcode
            0x01, // code[2]: Fallthrough
            0x07, // mask: bits 0, 1, 2 set
        ];
        let result = decode_blob_internal(&blob).unwrap();
        assert_eq!(result.instructions.len(), 3);
        assert!(matches!(result.instructions[0], (0, Instruction::Trap)));
        assert!(matches!(
            result.instructions[1],
            (1, Instruction::Unknown { opcode: 0xFF, .. })
        ));
        assert!(matches!(
            result.instructions[2],
            (2, Instruction::Fallthrough)
        ));
    }
}
