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
use functions::{build_call_graph, build_function_cfg, detect_functions};
use lifting::LiftedProgram;
use structuring::{DominatorTree, FunctionSignature, StructuralAnalysis};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verbosity {
    /// Default: only pseudo-code output
    Normal,
    /// -v/--verbose: include CFG, dataflow, and structural summaries
    Verbose,
    /// --debug: include raw instructions and all diagnostics
    Debug,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Parse flags
    let mut verbosity = Verbosity::Normal;
    let mut filename = None;

    for arg in &args[1..] {
        match arg.as_str() {
            "-v" | "--verbose" => verbosity = Verbosity::Verbose,
            "--debug" => verbosity = Verbosity::Debug,
            "-h" | "--help" => {
                eprintln!("Usage: {} [OPTIONS] <file.pvm>", args[0]);
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -v, --verbose  Show CFG, dataflow, and structural analysis");
                eprintln!("      --debug    Show raw instructions and all diagnostics");
                eprintln!("  -h, --help     Show this help message");
                return Ok(());
            }
            _ => {
                if arg.starts_with('-') {
                    eprintln!("Unknown option: {}", arg);
                    return Ok(());
                }
                filename = Some(arg.clone());
            }
        }
    }

    let filename = match filename {
        Some(f) => f,
        None => {
            eprintln!("Usage: {} [OPTIONS] <file.pvm>", args[0]);
            return Ok(());
        }
    };

    if verbosity >= Verbosity::Verbose {
        println!("Reading {}...", filename);
    }

    let mut file = fs::File::open(&filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Try SPI format first, fall back to raw blob if it fails
    let program = match decoder::decode_spi(&buffer) {
        Ok(prog) => {
            if verbosity >= Verbosity::Verbose {
                println!("Successfully decoded as SPI format");
            }
            prog
        }
        Err(e) => {
            if verbosity >= Verbosity::Verbose {
                eprintln!("SPI decode failed: {}, trying raw blob format...", e);
            }
            decoder::decode_blob(&buffer)?
        }
    };

    // Report unknown instructions (always on stderr as warnings)
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

    // Debug: raw instruction dump
    if verbosity >= Verbosity::Debug {
        println!("Jump Table: {:?}", program.jump_table);
        println!("\nInstructions:");
        for (pc, instr) in program.instructions.iter() {
            println!("  PC {:#06x}: {:?}", pc, instr);
        }
    }

    // Build global CFG
    let cfg = ControlFlowGraph::build(&program);
    if verbosity >= Verbosity::Debug {
        println!("\n=== Control Flow Graph ===");
        print_cfg(&cfg);
    }

    // Detect function boundaries
    let detected_functions = detect_functions(&cfg);
    if verbosity >= Verbosity::Verbose {
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
    }

    // Build call graph
    let call_graph = build_call_graph(&cfg, &detected_functions);
    if verbosity >= Verbosity::Verbose && !call_graph.is_empty() {
        println!("\n=== Call Graph ===");
        for func in &detected_functions {
            if let Some(calls) = call_graph.get(&func.entry_pc) {
                for call in calls {
                    println!(
                        "  {} (block {:#06x}) → {}",
                        func.name, call.caller_block_pc, call.callee_name
                    );
                }
            }
        }
    }

    // Build a flat lookup from callee_entry_pc → callee_name for pseudo-code emission.
    // This lets the emitter recognize Jump targets that are function entries.
    let mut call_targets: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    for calls in call_graph.values() {
        for call in calls {
            call_targets.insert(call.callee_entry_pc, call.callee_name.clone());
        }
    }

    // Process each function independently
    for func in &detected_functions {
        let func_cfg = build_function_cfg(&cfg, func);
        let dom_tree = DominatorTree::compute(&func_cfg);
        let dataflow = DataFlowAnalysis::analyze(&func_cfg);
        let mut lifted = LiftedProgram::analyze_with_dom_tree(&func_cfg, &dataflow, &dom_tree);
        lifted.call_targets = call_targets.clone();
        let structural = StructuralAnalysis::analyze_with_dom_tree(&func_cfg, &program, dom_tree);

        // Compute function signature from live-in registers at entry block
        let mut params: Vec<u8> = dataflow
            .live_in
            .get(&func.entry_pc)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        params.sort();
        let sig = FunctionSignature {
            name: func.name.clone(),
            params,
        };

        if verbosity >= Verbosity::Verbose {
            println!("\n{}", "=".repeat(60));
            println!(
                "=== Function: {} (entry @ {:#06x}) ===",
                func.name, func.entry_pc
            );
            println!("\n{}", dataflow.summarize());
            println!("{}", lifted.summarize());
            println!("{}", structural.summarize());
        }

        println!(
            "{}",
            structural.pseudo_code(&func_cfg, Some(&mut lifted), Some(&sig))
        );
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
