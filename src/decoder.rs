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
        if item_len != 4 {
            // In current spec, jump table entries are 4 bytes.
            // But let's follow the spec if it implies flexibility.
            // For now assume 4.
        }
        for _i in 0..jump_table_len {
            let entry = cursor.read_u32()?;
            jump_table.push(entry);
        }
    } else if jump_table_len > 0 && item_len == 0 {
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
    fn test_decode_invalid_opcode() {
        let result = decode_instruction(&[255], 1);
        assert!(result.is_err());
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
}
