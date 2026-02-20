use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
use wasm_pvm::pvm::Instruction;

mod cfg;
mod dataflow;
mod decoder;
mod functions;
mod instruction;
mod lifting;
mod structuring;
mod varint;

use cfg::ControlFlowGraph;
use dataflow::DataFlowAnalysis;
use functions::{build_function_cfg, detect_functions};
use lifting::LiftedProgram;
use structuring::StructuralAnalysis;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file.pvm>", args[0]);
        return Ok(());
    }

    let filename = &args[1];
    println!("Reading {}...", filename);

    let mut file = fs::File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Try SPI format first, fall back to raw blob if it fails
    let program = match decoder::decode_spi(&buffer) {
        Ok(prog) => {
            println!("Successfully decoded as SPI format");
            prog
        }
        Err(e) => {
            eprintln!("SPI decode failed: {}, trying raw blob format...", e);
            decoder::decode_blob(&buffer)?
        }
    };

    // Report unknown instructions
    let mut unknown_opcodes: HashMap<u8, usize> = HashMap::new();
    for (_, instr) in &program.instructions {
        if let Instruction::Unknown { opcode, .. } = instr {
            *unknown_opcodes.entry(*opcode).or_default() += 1;
        }
    }
    if !unknown_opcodes.is_empty() {
        let mut sorted: Vec<_> = unknown_opcodes.iter().collect();
        sorted.sort_by_key(|(op, _)| **op);
        eprintln!(
            "Warning: {} unknown opcode(s) encountered:",
            sorted.iter().map(|(_, c)| *c).sum::<usize>()
        );
        for (opcode, count) in sorted {
            eprintln!("  opcode {:#04x}: {} occurrence(s)", opcode, count);
        }
        eprintln!();
    }

    println!("Jump Table: {:?}", program.jump_table);
    println!("\nInstructions:");
    for (pc, instr) in program.instructions.iter() {
        println!("  PC {:#06x}: {:?}", pc, instr);
    }

    // Build global CFG
    println!("\n=== Control Flow Graph ===");
    let cfg = ControlFlowGraph::build(&program);
    print_cfg(&cfg);

    // Detect function boundaries
    let detected_functions = detect_functions(&cfg);
    println!(
        "\n=== Function Detection ===\nDetected {} function(s):",
        detected_functions.len()
    );
    for func in &detected_functions {
        let mut sorted_blocks: Vec<usize> = func.block_pcs.iter().copied().collect();
        sorted_blocks.sort();
        println!(
            "  {} @ {:#06x} ({} blocks: {:?})",
            func.name,
            func.entry_pc,
            func.block_pcs.len(),
            sorted_blocks
        );
    }

    // Process each function independently
    for func in &detected_functions {
        println!("\n{}", "=".repeat(60));
        println!(
            "=== Function: {} (entry @ {:#06x}) ===",
            func.name, func.entry_pc
        );

        let func_cfg = build_function_cfg(&cfg, func);

        let dataflow = DataFlowAnalysis::analyze(&func_cfg);
        println!("\n{}", dataflow.summarize());

        let mut lifted = LiftedProgram::analyze(&func_cfg, &dataflow);
        println!("{}", lifted.summarize());

        let structural = StructuralAnalysis::analyze(&func_cfg, &program);
        println!("{}", structural.summarize());
        println!("{}", structural.pseudo_code(&func_cfg, Some(&mut lifted)));
    }

    Ok(())
}

fn print_cfg(cfg: &ControlFlowGraph) {
    println!("Entry PC: {:#06x}", cfg.entry_pc);
    println!("Number of blocks: {}", cfg.blocks.len());

    let mut block_pcs: Vec<usize> = cfg.blocks.keys().copied().collect();
    block_pcs.sort();

    for block_pc in block_pcs {
        if let Some(block) = cfg.blocks.get(&block_pc) {
            println!("\nBlock @ {:#06x} - {:#06x}:", block.start_pc, block.end_pc);
            for (pc, instr) in &block.instructions {
                println!("    {:#06x}: {:?}", pc, instr);
            }

            if !block.successors.is_empty() {
                print!("  Successors: ");
                for (i, succ) in block.successors.iter().enumerate() {
                    if i > 0 {
                        print!(", ");
                    }
                    print!("{:#06x}", succ);
                }
                println!();
            } else {
                println!("  Successors: (none)");
            }

            if !block.predecessors.is_empty() {
                print!("  Predecessors: ");
                for (i, pred) in block.predecessors.iter().enumerate() {
                    if i > 0 {
                        print!(", ");
                    }
                    print!("{:#06x}", pred);
                }
                println!();
            }
        }
    }
}
