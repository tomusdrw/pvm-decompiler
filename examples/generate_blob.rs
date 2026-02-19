use std::fs;
use wasm_pvm::pvm::{Instruction, ProgramBlob};

fn main() -> std::io::Result<()> {
    let instructions = vec![
        Instruction::LoadImm { reg: 0, value: 42 }, // 0x0000 (len 3: 51 00 2a)
        Instruction::LoadImm { reg: 1, value: 100 }, // 0x0003 (len 3: 51 01 64)
        Instruction::Add32 {
            dst: 2,
            src1: 0,
            src2: 1,
        }, // 0x0006 (len 3: be 10 02)
        // Jump to Fallthrough (skip Trap).
        // Current PC: 0x0009.
        // Jump len: 5.
        // Trap at: 0x000e (len 1).
        // Fallthrough at: 0x000f.
        // Offset = 0x000f - 0x0009 = 6.
        Instruction::Jump { offset: 6 }, // 0x0009 (len 5)
        Instruction::Trap,               // 0x000e (len 1)
        Instruction::Fallthrough,        // 0x000f (len 1)
    ];

    let blob = ProgramBlob::new(instructions);
    let encoded = blob.encode();

    fs::write("test.pvm", encoded)?;
    println!("Wrote test.pvm");
    Ok(())
}
