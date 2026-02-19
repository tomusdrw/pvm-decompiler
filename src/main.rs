use std::env;
use std::fs;
use std::io::Read;

mod cfg;
mod decoder;
mod varint;

use cfg::ControlFlowGraph;

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

    let program = decoder::decode_blob(&buffer)?;

    println!("Jump Table: {:?}", program.jump_table);
    println!("\nInstructions:");
    for (pc, instr) in program.instructions.iter() {
        println!("  PC {:#06x}: {:?}", pc, instr);
    }

    // Build and print CFG
    println!("\n=== Control Flow Graph ===");
    let cfg = ControlFlowGraph::build(&program);
    print_cfg(&cfg);

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
