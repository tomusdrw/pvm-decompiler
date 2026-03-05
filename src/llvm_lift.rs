//! LLVM IR Lifter
//!
//! Translates PVM instructions and control flow graphs into LLVM IR text format (.ll).
//! The generated IR uses allocas for PVM registers (promoted to SSA by LLVM's mem2reg),
//! a global byte array for PVM memory, and preserves the CFG structure.

use std::collections::HashSet;
use std::fmt::Write;

use crate::cfg::{BasicBlock, ControlFlowGraph};
use crate::decoder::DecodedProgram;
use crate::functions::Function;
use crate::instruction::{BinOp, BitWidth, InstructionShape, MemWidth, UnaryOp};

/// PVM register count (r0..r12).
const NUM_REGS: u8 = 13;

/// Default PVM memory size (256 MB).
const PVM_MEMORY_SIZE: u64 = 256 * 1024 * 1024;

/// Generate LLVM IR text for an entire PVM program.
pub fn lift_program(
    program: &DecodedProgram,
    cfg: &ControlFlowGraph,
    functions: &[Function],
) -> String {
    let mut out = String::with_capacity(64 * 1024);

    // Module header
    writeln!(out, "; ModuleID = 'pvm_program'").unwrap();
    writeln!(out, "source_filename = \"pvm_program.pvm\"").unwrap();
    writeln!(out, "target datalayout = \"e-m:e-p:64:64-i64:64-n32:64\"").unwrap();
    writeln!(out, "target triple = \"x86_64-unknown-linux-gnu\"").unwrap();
    writeln!(out).unwrap();

    // PVM memory as a global byte array
    writeln!(
        out,
        "@pvm_memory = global [{} x i8] zeroinitializer, align 16",
        PVM_MEMORY_SIZE
    )
    .unwrap();
    writeln!(out).unwrap();

    // Declare external functions
    writeln!(out, "; External declarations for PVM host calls").unwrap();
    writeln!(
        out,
        "declare void @pvm_ecalli(i32) ; External call interface"
    )
    .unwrap();
    writeln!(out, "declare void @pvm_trap() noreturn ; Trap/halt").unwrap();
    writeln!(out, "declare i64 @pvm_sbrk(i64) ; Memory allocation (sbrk)").unwrap();

    // Intrinsics
    writeln!(out, "declare i32 @llvm.ctpop.i32(i32)").unwrap();
    writeln!(out, "declare i64 @llvm.ctpop.i64(i64)").unwrap();
    writeln!(out, "declare i32 @llvm.ctlz.i32(i32, i1)").unwrap();
    writeln!(out, "declare i64 @llvm.ctlz.i64(i64, i1)").unwrap();
    writeln!(out, "declare i32 @llvm.cttz.i32(i32, i1)").unwrap();
    writeln!(out, "declare i64 @llvm.cttz.i64(i64, i1)").unwrap();
    writeln!(out, "declare i32 @llvm.fshl.i32(i32, i32, i32)").unwrap();
    writeln!(out, "declare i64 @llvm.fshl.i64(i64, i64, i64)").unwrap();
    writeln!(out, "declare i32 @llvm.fshr.i32(i32, i32, i32)").unwrap();
    writeln!(out, "declare i64 @llvm.fshr.i64(i64, i64, i64)").unwrap();
    writeln!(out, "declare i16 @llvm.bswap.i16(i16)").unwrap();
    writeln!(out, "declare i32 @llvm.bswap.i32(i32)").unwrap();
    writeln!(out, "declare i64 @llvm.bswap.i64(i64)").unwrap();
    writeln!(out).unwrap();

    // If no functions detected, emit the whole program as one function
    if functions.is_empty() {
        lift_single_function(
            &mut out,
            "main",
            program,
            cfg,
            &cfg.blocks.keys().copied().collect(),
            0,
        );
    } else {
        // Emit each function
        for func in functions {
            lift_single_function(
                &mut out,
                &func.name,
                program,
                cfg,
                &func.block_pcs,
                func.entry_pc,
            );
        }
    }

    out
}

/// Emit LLVM IR for a single PVM function.
fn lift_single_function(
    out: &mut String,
    name: &str,
    program: &DecodedProgram,
    cfg: &ControlFlowGraph,
    block_pcs: &HashSet<usize>,
    entry_pc: usize,
) {
    // Collect blocks belonging to this function, sorted by PC
    let mut func_blocks: Vec<&BasicBlock> = block_pcs
        .iter()
        .filter_map(|pc| cfg.blocks.get(pc))
        .collect();
    func_blocks.sort_by_key(|b| b.start_pc);

    if func_blocks.is_empty() {
        return;
    }

    // Function signature: takes no args, returns i64 (r0)
    // PVM convention used by this LLVM lift path:
    // r0 = return address, r1 = SP, r2-r6 = scratch, r7 = return value/args ptr,
    // r8 = args len, r9-r12 = callee-saved.
    writeln!(out, "define i64 @{}() {{", sanitize_name(name)).unwrap();

    // Entry block: allocate registers
    writeln!(out, "entry:").unwrap();
    for reg in 0..NUM_REGS {
        writeln!(out, "  %r{} = alloca i64, align 8", reg).unwrap();
    }

    // Initialize registers to 0
    for reg in 0..NUM_REGS {
        writeln!(out, "  store i64 0, ptr %r{}, align 8", reg).unwrap();
    }

    // Initialize SP (r1) with a stack pointer value if memory_base is known
    if let Some(mem_base) = program.memory_base {
        writeln!(
            out,
            "  store i64 {}, ptr %r1, align 8 ; SP = memory_base",
            mem_base
        )
        .unwrap();
    }

    // Jump to the entry basic block
    writeln!(out, "  br label %bb_{:04x}", entry_pc).unwrap();
    writeln!(out).unwrap();

    // SSA temporary counter for this function
    let mut tmp_counter = 0u64;
    let mut exit_labels_emitted: HashSet<usize> = HashSet::new();

    // Emit each basic block
    for block in &func_blocks {
        writeln!(out, "bb_{:04x}:", block.start_pc).unwrap();

        // Emit each instruction
        for (pc, instr) in &block.instructions {
            let shape = InstructionShape::classify(instr);
            emit_instruction(out, &shape, *pc, program, &mut tmp_counter);
        }

        // Emit terminator
        emit_terminator(
            out,
            block,
            program,
            block_pcs,
            &mut exit_labels_emitted,
            &mut tmp_counter,
        );
        writeln!(out).unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

/// Emit LLVM IR for a single PVM instruction.
fn emit_instruction(
    out: &mut String,
    shape: &InstructionShape,
    _pc: usize,
    _program: &DecodedProgram,
    tmp: &mut u64,
) {
    match shape {
        InstructionShape::NoOp { .. } => {
            // No-ops: trap handled by terminator, fallthrough is implicit
        }

        InstructionShape::LoadImm { dst, value } => {
            writeln!(out, "  store i64 {}, ptr %r{}, align 8", value, dst).unwrap();
        }

        InstructionShape::BinReg {
            op,
            width,
            dst,
            src1,
            src2,
        } => {
            let t1 = next_tmp(tmp);
            let t2 = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", t1, src1).unwrap();
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", t2, src2).unwrap();
            emit_binop(out, op, width, *dst, &t1, &t2, tmp);
        }

        InstructionShape::BinImm {
            op,
            width,
            dst,
            src,
            value,
        } => {
            let t1 = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", t1, src).unwrap();
            let t2 = next_tmp(tmp);
            writeln!(out, "  {} = add i64 0, {}", t2, *value as i64).unwrap();
            emit_binop(out, op, width, *dst, &t1, &t2, tmp);
        }

        InstructionShape::BinImmRev {
            op,
            width,
            dst,
            src,
            value,
        } => {
            // dst = value op src (reversed)
            let t1 = next_tmp(tmp);
            writeln!(out, "  {} = add i64 0, {}", t1, *value as i64).unwrap();
            let t2 = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", t2, src).unwrap();
            emit_binop(out, op, width, *dst, &t1, &t2, tmp);
        }

        InstructionShape::Unary { op, dst, src } => {
            let t1 = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", t1, src).unwrap();
            emit_unary(out, op, *dst, &t1, tmp);
        }

        InstructionShape::Load {
            width,
            dst,
            base,
            offset,
        } => {
            emit_memory_load(out, width, *dst, Some(*base), *offset as i64, tmp);
        }

        InstructionShape::Store {
            width,
            base,
            src,
            offset,
        } => {
            emit_memory_store(out, width, Some(*base), *offset as i64, *src, tmp);
        }

        InstructionShape::LoadAbsolute {
            width,
            dst,
            address,
        } => {
            emit_memory_load(out, width, *dst, None, *address as i64, tmp);
        }

        InstructionShape::StoreAbsolute {
            width,
            src,
            address,
        } => {
            emit_memory_store(out, width, None, *address as i64, *src, tmp);
        }

        InstructionShape::StoreImm {
            width,
            address,
            value,
        } => {
            emit_memory_store_imm(out, width, None, *address as i64, *value as i64, tmp);
        }

        InstructionShape::StoreImmInd {
            width,
            base,
            offset,
            value,
        } => {
            emit_memory_store_imm(out, width, Some(*base), *offset as i64, *value as i64, tmp);
        }

        InstructionShape::CmovReg {
            is_zero,
            dst,
            src,
            cond,
        } => {
            let tc = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", tc, cond).unwrap();
            let cmp = next_tmp(tmp);
            if *is_zero {
                writeln!(out, "  {} = icmp eq i64 {}, 0", cmp, tc).unwrap();
            } else {
                writeln!(out, "  {} = icmp ne i64 {}, 0", cmp, tc).unwrap();
            }
            let ts = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", ts, src).unwrap();
            let td = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", td, dst).unwrap();
            let sel = next_tmp(tmp);
            writeln!(out, "  {} = select i1 {}, i64 {}, i64 {}", sel, cmp, ts, td).unwrap();
            writeln!(out, "  store i64 {}, ptr %r{}, align 8", sel, dst).unwrap();
        }

        InstructionShape::CmovImm {
            is_zero,
            dst,
            cond,
            value,
        } => {
            let tc = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", tc, cond).unwrap();
            let cmp = next_tmp(tmp);
            if *is_zero {
                writeln!(out, "  {} = icmp eq i64 {}, 0", cmp, tc).unwrap();
            } else {
                writeln!(out, "  {} = icmp ne i64 {}, 0", cmp, tc).unwrap();
            }
            let td = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r{}, align 8", td, dst).unwrap();
            let sel = next_tmp(tmp);
            writeln!(
                out,
                "  {} = select i1 {}, i64 {}, i64 {}",
                sel, cmp, *value as i64, td
            )
            .unwrap();
            writeln!(out, "  store i64 {}, ptr %r{}, align 8", sel, dst).unwrap();
        }

        InstructionShape::LoadImmJump { dst, value, .. } => {
            // Load immediate (jump handled by terminator)
            writeln!(out, "  store i64 {}, ptr %r{}, align 8", *value as i64, dst).unwrap();
        }

        InstructionShape::LoadImmJumpInd {
            base: _,
            dst,
            value,
        } => {
            // Load immediate (indirect jump handled by terminator)
            writeln!(out, "  store i64 {}, ptr %r{}, align 8", *value as i64, dst).unwrap();
        }

        InstructionShape::Ecalli { index } => {
            writeln!(out, "  call void @pvm_ecalli(i32 {})", index).unwrap();
        }

        // Branches and jumps handled by emit_terminator
        InstructionShape::Jump { .. }
        | InstructionShape::JumpInd { .. }
        | InstructionShape::BranchImm { .. }
        | InstructionShape::BranchReg { .. } => {}

        InstructionShape::Unknown { opcode } => {
            writeln!(out, "  ; unknown opcode 0x{:02x}", opcode).unwrap();
        }
    }
}

/// Emit the terminator for a basic block.
fn emit_terminator(
    out: &mut String,
    block: &BasicBlock,
    program: &DecodedProgram,
    func_block_pcs: &HashSet<usize>,
    exit_labels_emitted: &mut HashSet<usize>,
    tmp: &mut u64,
) {
    if let Some((pc, instr)) = block.instructions.last() {
        let shape = InstructionShape::classify(instr);
        match &shape {
            InstructionShape::NoOp { name: "trap" } => {
                // Load r0 for return value before trapping
                let t = next_tmp(tmp);
                writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                writeln!(out, "  call void @pvm_trap()").unwrap();
                writeln!(out, "  unreachable").unwrap();
            }

            InstructionShape::Jump { offset } => {
                let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                if func_block_pcs.contains(&target) {
                    writeln!(out, "  br label %bb_{:04x}", target).unwrap();
                } else {
                    // Jump to external function - emit as return
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
            }

            InstructionShape::LoadImmJump { offset, .. } => {
                let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                if func_block_pcs.contains(&target) {
                    writeln!(out, "  br label %bb_{:04x}", target).unwrap();
                } else {
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
            }

            InstructionShape::JumpInd { reg } => {
                // Indirect jump - emit as switch on jump table or return
                if !program.jump_table.is_empty() {
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r{}, align 8", t, reg).unwrap();
                    emit_indirect_jump(out, &t, program, func_block_pcs, tmp);
                } else {
                    // No jump table: treat as return
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
            }

            InstructionShape::LoadImmJumpInd { .. } => {
                // Combined load + indirect jump - typically a return or tail call
                let t = next_tmp(tmp);
                writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                writeln!(out, "  ret i64 {}", t).unwrap();
            }

            InstructionShape::BranchImm {
                cond,
                reg,
                value,
                offset,
            } => {
                let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                let fallthrough = block.end_pc;

                let tr = next_tmp(tmp);
                writeln!(out, "  {} = load i64, ptr %r{}, align 8", tr, reg).unwrap();

                let cmp = next_tmp(tmp);
                let llvm_cond = branch_cond_to_icmp(cond);
                writeln!(
                    out,
                    "  {} = icmp {} i64 {}, {}",
                    cmp, llvm_cond, tr, *value as i64
                )
                .unwrap();

                let target_label = if func_block_pcs.contains(&target) {
                    format!("bb_{:04x}", target)
                } else {
                    format!("bb_exit_{:04x}", target)
                };
                let fall_label = if func_block_pcs.contains(&fallthrough) {
                    format!("bb_{:04x}", fallthrough)
                } else {
                    format!("bb_exit_{:04x}", fallthrough)
                };

                writeln!(
                    out,
                    "  br i1 {}, label %{}, label %{}",
                    cmp, target_label, fall_label
                )
                .unwrap();

                // Emit exit blocks if needed
                if !func_block_pcs.contains(&target) && exit_labels_emitted.insert(target) {
                    writeln!(out, "\n{}:", target_label).unwrap();
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
                if !func_block_pcs.contains(&fallthrough) && exit_labels_emitted.insert(fallthrough)
                {
                    writeln!(out, "\n{}:", fall_label).unwrap();
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
            }

            InstructionShape::BranchReg {
                cond,
                reg1,
                reg2,
                offset,
            } => {
                let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                let fallthrough = block.end_pc;

                let t1 = next_tmp(tmp);
                let t2 = next_tmp(tmp);
                writeln!(out, "  {} = load i64, ptr %r{}, align 8", t1, reg1).unwrap();
                writeln!(out, "  {} = load i64, ptr %r{}, align 8", t2, reg2).unwrap();

                let cmp = next_tmp(tmp);
                let llvm_cond = branch_cond_to_icmp(cond);
                writeln!(out, "  {} = icmp {} i64 {}, {}", cmp, llvm_cond, t1, t2).unwrap();

                let target_label = if func_block_pcs.contains(&target) {
                    format!("bb_{:04x}", target)
                } else {
                    format!("bb_exit_{:04x}", target)
                };
                let fall_label = if func_block_pcs.contains(&fallthrough) {
                    format!("bb_{:04x}", fallthrough)
                } else {
                    format!("bb_exit_{:04x}", fallthrough)
                };

                writeln!(
                    out,
                    "  br i1 {}, label %{}, label %{}",
                    cmp, target_label, fall_label
                )
                .unwrap();

                if !func_block_pcs.contains(&target) && exit_labels_emitted.insert(target) {
                    writeln!(out, "\n{}:", target_label).unwrap();
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
                if !func_block_pcs.contains(&fallthrough) && exit_labels_emitted.insert(fallthrough)
                {
                    writeln!(out, "\n{}:", fall_label).unwrap();
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
            }

            InstructionShape::Unknown { opcode } => {
                writeln!(out, "  ; unknown opcode 0x{:02x}", opcode).unwrap();
                writeln!(out, "  call void @pvm_trap()").unwrap();
                writeln!(out, "  unreachable").unwrap();
            }

            _ => {
                // Non-terminator at end of block: fall through
                if !block.successors.is_empty() {
                    let next = block.successors[0];
                    if func_block_pcs.contains(&next) {
                        writeln!(out, "  br label %bb_{:04x}", next).unwrap();
                    } else {
                        let t = next_tmp(tmp);
                        writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                        writeln!(out, "  ret i64 {}", t).unwrap();
                    }
                } else {
                    let t = next_tmp(tmp);
                    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                    writeln!(out, "  ret i64 {}", t).unwrap();
                }
            }
        }
    } else {
        // Empty block - fall through or return
        if !block.successors.is_empty() {
            let next = block.successors[0];
            if func_block_pcs.contains(&next) {
                writeln!(out, "  br label %bb_{:04x}", next).unwrap();
            } else {
                let t = next_tmp(tmp);
                writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
                writeln!(out, "  ret i64 {}", t).unwrap();
            }
        } else {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
            writeln!(out, "  ret i64 {}", t).unwrap();
        }
    }
}

/// Emit LLVM IR for a binary operation.
fn emit_binop(
    out: &mut String,
    op: &BinOp,
    width: &BitWidth,
    dst: u8,
    lhs: &str,
    rhs: &str,
    tmp: &mut u64,
) {
    let is_32 = matches!(width, BitWidth::W32);

    // If 32-bit, truncate inputs first
    let (l, r) = if is_32 {
        let tl = next_tmp(tmp);
        let tr = next_tmp(tmp);
        writeln!(out, "  {} = trunc i64 {} to i32", tl, lhs).unwrap();
        writeln!(out, "  {} = trunc i64 {} to i32", tr, rhs).unwrap();
        (tl, tr)
    } else {
        (lhs.to_string(), rhs.to_string())
    };

    let ty = if is_32 { "i32" } else { "i64" };
    let result = next_tmp(tmp);

    match op {
        BinOp::Add => writeln!(out, "  {} = add {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::Sub => writeln!(out, "  {} = sub {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::Mul => writeln!(out, "  {} = mul {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::DivU => writeln!(out, "  {} = udiv {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::DivS => writeln!(out, "  {} = sdiv {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::RemU => writeln!(out, "  {} = urem {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::RemS => writeln!(out, "  {} = srem {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::Shl => writeln!(out, "  {} = shl {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::ShrU => writeln!(out, "  {} = lshr {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::ShrS => writeln!(out, "  {} = ashr {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::And => writeln!(out, "  {} = and {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::Or => writeln!(out, "  {} = or {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::Xor => writeln!(out, "  {} = xor {} {}, {}", result, ty, l, r).unwrap(),
        BinOp::LtU
        | BinOp::LtS
        | BinOp::GeU
        | BinOp::GeS
        | BinOp::GtU
        | BinOp::GtS
        | BinOp::LeU
        | BinOp::LeS => {
            let icmp = match op {
                BinOp::LtU => "ult",
                BinOp::LtS => "slt",
                BinOp::GeU => "uge",
                BinOp::GeS => "sge",
                BinOp::GtU => "ugt",
                BinOp::GtS => "sgt",
                BinOp::LeU => "ule",
                BinOp::LeS => "sle",
                _ => unreachable!(),
            };
            writeln!(out, "  {} = icmp {} {} {}, {}", result, icmp, ty, l, r).unwrap();
            let ext = next_tmp(tmp);
            writeln!(out, "  {} = zext i1 {} to {}", ext, result, ty).unwrap();
            if is_32 {
                let ext64 = next_tmp(tmp);
                writeln!(out, "  {} = zext i32 {} to i64", ext64, ext).unwrap();
                writeln!(out, "  store i64 {}, ptr %r{}, align 8", ext64, dst).unwrap();
            } else {
                writeln!(out, "  store i64 {}, ptr %r{}, align 8", ext, dst).unwrap();
            }
            return;
        }
        BinOp::NegAdd => {
            // dst = rhs - lhs (value - src in original)
            writeln!(out, "  {} = sub {} {}, {}", result, ty, l, r).unwrap();
        }
        BinOp::RotL => {
            writeln!(
                out,
                "  {} = call {} @llvm.fshl.{}({} {}, {} {}, {} {})",
                result, ty, ty, ty, l, ty, l, ty, r
            )
            .unwrap();
        }
        BinOp::RotR => {
            writeln!(
                out,
                "  {} = call {} @llvm.fshr.{}({} {}, {} {}, {} {})",
                result, ty, ty, ty, l, ty, l, ty, r
            )
            .unwrap();
        }
        BinOp::MulUpperSS | BinOp::MulUpperUU | BinOp::MulUpperSU => {
            // 128-bit multiply, take upper 64 bits
            let ext_op = match op {
                BinOp::MulUpperSS => "sext",
                BinOp::MulUpperUU => "zext",
                BinOp::MulUpperSU => "sext", // first operand signed
                _ => unreachable!(),
            };
            let el = next_tmp(tmp);
            let er = next_tmp(tmp);
            writeln!(out, "  {} = {} i64 {} to i128", el, ext_op, l).unwrap();
            let ext_op2 = match op {
                BinOp::MulUpperSU => "zext", // second operand unsigned
                _ => ext_op,
            };
            writeln!(out, "  {} = {} i64 {} to i128", er, ext_op2, r).unwrap();
            let mul = next_tmp(tmp);
            writeln!(out, "  {} = mul i128 {}, {}", mul, el, er).unwrap();
            let shift = next_tmp(tmp);
            writeln!(out, "  {} = lshr i128 {}, 64", shift, mul).unwrap();
            writeln!(out, "  {} = trunc i128 {} to i64", result, shift).unwrap();
            writeln!(out, "  store i64 {}, ptr %r{}, align 8", result, dst).unwrap();
            return;
        }
        BinOp::AndInv => {
            let inv = next_tmp(tmp);
            writeln!(out, "  {} = xor {} {}, -1", inv, ty, r).unwrap();
            writeln!(out, "  {} = and {} {}, {}", result, ty, l, inv).unwrap();
        }
        BinOp::OrInv => {
            let inv = next_tmp(tmp);
            writeln!(out, "  {} = xor {} {}, -1", inv, ty, r).unwrap();
            writeln!(out, "  {} = or {} {}, {}", result, ty, l, inv).unwrap();
        }
        BinOp::Xnor => {
            let x = next_tmp(tmp);
            writeln!(out, "  {} = xor {} {}, {}", x, ty, l, r).unwrap();
            writeln!(out, "  {} = xor {} {}, -1", result, ty, x).unwrap();
        }
        BinOp::Max => {
            let cmp = next_tmp(tmp);
            writeln!(out, "  {} = icmp sgt {} {}, {}", cmp, ty, l, r).unwrap();
            writeln!(
                out,
                "  {} = select i1 {}, {} {}, {} {}",
                result, cmp, ty, l, ty, r
            )
            .unwrap();
        }
        BinOp::MaxU => {
            let cmp = next_tmp(tmp);
            writeln!(out, "  {} = icmp ugt {} {}, {}", cmp, ty, l, r).unwrap();
            writeln!(
                out,
                "  {} = select i1 {}, {} {}, {} {}",
                result, cmp, ty, l, ty, r
            )
            .unwrap();
        }
        BinOp::Min => {
            let cmp = next_tmp(tmp);
            writeln!(out, "  {} = icmp slt {} {}, {}", cmp, ty, l, r).unwrap();
            writeln!(
                out,
                "  {} = select i1 {}, {} {}, {} {}",
                result, cmp, ty, l, ty, r
            )
            .unwrap();
        }
        BinOp::MinU => {
            let cmp = next_tmp(tmp);
            writeln!(out, "  {} = icmp ult {} {}, {}", cmp, ty, l, r).unwrap();
            writeln!(
                out,
                "  {} = select i1 {}, {} {}, {} {}",
                result, cmp, ty, l, ty, r
            )
            .unwrap();
        } // Eq and Ne only appear as branch conditions in PVM, not as BinOp variants
    }

    // Extend 32-bit result back to 64-bit and store
    if is_32 {
        let ext = next_tmp(tmp);
        writeln!(out, "  {} = zext i32 {} to i64", ext, result).unwrap();
        writeln!(out, "  store i64 {}, ptr %r{}, align 8", ext, dst).unwrap();
    } else {
        writeln!(out, "  store i64 {}, ptr %r{}, align 8", result, dst).unwrap();
    }
}

/// Emit LLVM IR for a unary operation.
fn emit_unary(out: &mut String, op: &UnaryOp, dst: u8, src: &str, tmp: &mut u64) {
    let result = next_tmp(tmp);
    match op {
        UnaryOp::Not => {
            // Logical NOT: result = (src == 0) ? 1 : 0
            let cmp = next_tmp(tmp);
            writeln!(out, "  {} = icmp eq i64 {}, 0", cmp, src).unwrap();
            writeln!(out, "  {} = zext i1 {} to i64", result, cmp).unwrap();
        }
        UnaryOp::Sext8 => {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = trunc i64 {} to i8", t, src).unwrap();
            writeln!(out, "  {} = sext i8 {} to i64", result, t).unwrap();
        }
        UnaryOp::Sext16 => {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = trunc i64 {} to i16", t, src).unwrap();
            writeln!(out, "  {} = sext i16 {} to i64", result, t).unwrap();
        }
        UnaryOp::Zext16 => {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = trunc i64 {} to i16", t, src).unwrap();
            writeln!(out, "  {} = zext i16 {} to i64", result, t).unwrap();
        }
        UnaryOp::Popcnt32 => {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = trunc i64 {} to i32", t, src).unwrap();
            let p = next_tmp(tmp);
            writeln!(out, "  {} = call i32 @llvm.ctpop.i32(i32 {})", p, t).unwrap();
            writeln!(out, "  {} = zext i32 {} to i64", result, p).unwrap();
        }
        UnaryOp::Popcnt64 => {
            let p = next_tmp(tmp);
            writeln!(out, "  {} = call i64 @llvm.ctpop.i64(i64 {})", p, src).unwrap();
            writeln!(out, "  {} = add i64 {}, 0", result, p).unwrap();
        }
        UnaryOp::Clz32 => {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = trunc i64 {} to i32", t, src).unwrap();
            let c = next_tmp(tmp);
            writeln!(
                out,
                "  {} = call i32 @llvm.ctlz.i32(i32 {}, i1 false)",
                c, t
            )
            .unwrap();
            writeln!(out, "  {} = zext i32 {} to i64", result, c).unwrap();
        }
        UnaryOp::Clz64 => {
            writeln!(
                out,
                "  {} = call i64 @llvm.ctlz.i64(i64 {}, i1 false)",
                result, src
            )
            .unwrap();
        }
        UnaryOp::Ctz32 => {
            let t = next_tmp(tmp);
            writeln!(out, "  {} = trunc i64 {} to i32", t, src).unwrap();
            let c = next_tmp(tmp);
            writeln!(
                out,
                "  {} = call i32 @llvm.cttz.i32(i32 {}, i1 false)",
                c, t
            )
            .unwrap();
            writeln!(out, "  {} = zext i32 {} to i64", result, c).unwrap();
        }
        UnaryOp::Ctz64 => {
            writeln!(
                out,
                "  {} = call i64 @llvm.cttz.i64(i64 {}, i1 false)",
                result, src
            )
            .unwrap();
        }
        UnaryOp::Sbrk => {
            writeln!(out, "  {} = call i64 @pvm_sbrk(i64 {})", result, src).unwrap();
        }
        UnaryOp::Bswap => {
            writeln!(out, "  {} = call i64 @llvm.bswap.i64(i64 {})", result, src).unwrap();
        }
    }
    writeln!(out, "  store i64 {}, ptr %r{}, align 8", result, dst).unwrap();
}

/// Emit a memory load from PVM memory.
fn emit_memory_load(
    out: &mut String,
    width: &MemWidth,
    dst: u8,
    base_reg: Option<u8>,
    offset: i64,
    tmp: &mut u64,
) {
    // Compute address
    let addr = if let Some(reg) = base_reg {
        let t = next_tmp(tmp);
        writeln!(out, "  {} = load i64, ptr %r{}, align 8", t, reg).unwrap();
        if offset != 0 {
            let a = next_tmp(tmp);
            writeln!(out, "  {} = add i64 {}, {}", a, t, offset).unwrap();
            a
        } else {
            t
        }
    } else {
        let a = next_tmp(tmp);
        writeln!(out, "  {} = add i64 0, {}", a, offset).unwrap();
        a
    };

    // GEP into pvm_memory
    let ptr = next_tmp(tmp);
    writeln!(
        out,
        "  {} = getelementptr [{} x i8], ptr @pvm_memory, i64 0, i64 {}",
        ptr, PVM_MEMORY_SIZE, addr
    )
    .unwrap();

    // Load with appropriate width
    let (load_ty, needs_ext) = match width {
        MemWidth::U8 => ("i8", Some(("zext", "i8"))),
        MemWidth::I8 => ("i8", Some(("sext", "i8"))),
        MemWidth::U16 => ("i16", Some(("zext", "i16"))),
        MemWidth::I16 => ("i16", Some(("sext", "i16"))),
        MemWidth::U32 => ("i32", Some(("zext", "i32"))),
        MemWidth::I32 => ("i32", Some(("sext", "i32"))),
        MemWidth::U64 => ("i64", None),
    };

    let loaded = next_tmp(tmp);
    writeln!(out, "  {} = load {}, ptr {}", loaded, load_ty, ptr).unwrap();

    if let Some((ext_op, from_ty)) = needs_ext {
        let extended = next_tmp(tmp);
        writeln!(
            out,
            "  {} = {} {} {} to i64",
            extended, ext_op, from_ty, loaded
        )
        .unwrap();
        writeln!(out, "  store i64 {}, ptr %r{}, align 8", extended, dst).unwrap();
    } else {
        writeln!(out, "  store i64 {}, ptr %r{}, align 8", loaded, dst).unwrap();
    }
}

/// Emit a memory store to PVM memory (from register).
fn emit_memory_store(
    out: &mut String,
    width: &MemWidth,
    base_reg: Option<u8>,
    offset: i64,
    src_reg: u8,
    tmp: &mut u64,
) {
    let val = next_tmp(tmp);
    writeln!(out, "  {} = load i64, ptr %r{}, align 8", val, src_reg).unwrap();

    emit_memory_store_value(out, width, base_reg, offset, &val, tmp);
}

/// Emit a memory store to PVM memory (immediate value).
fn emit_memory_store_imm(
    out: &mut String,
    width: &MemWidth,
    base_reg: Option<u8>,
    offset: i64,
    value: i64,
    tmp: &mut u64,
) {
    let val = next_tmp(tmp);
    writeln!(out, "  {} = add i64 0, {}", val, value).unwrap();

    emit_memory_store_value(out, width, base_reg, offset, &val, tmp);
}

/// Shared store-value logic.
fn emit_memory_store_value(
    out: &mut String,
    width: &MemWidth,
    base_reg: Option<u8>,
    offset: i64,
    val: &str,
    tmp: &mut u64,
) {
    // Compute address
    let addr = if let Some(reg) = base_reg {
        let t = next_tmp(tmp);
        writeln!(out, "  {} = load i64, ptr %r{}, align 8", t, reg).unwrap();
        if offset != 0 {
            let a = next_tmp(tmp);
            writeln!(out, "  {} = add i64 {}, {}", a, t, offset).unwrap();
            a
        } else {
            t
        }
    } else {
        let a = next_tmp(tmp);
        writeln!(out, "  {} = add i64 0, {}", a, offset).unwrap();
        a
    };

    // GEP into pvm_memory
    let ptr = next_tmp(tmp);
    writeln!(
        out,
        "  {} = getelementptr [{} x i8], ptr @pvm_memory, i64 0, i64 {}",
        ptr, PVM_MEMORY_SIZE, addr
    )
    .unwrap();

    // Truncate value if needed and store
    let store_ty = match width {
        MemWidth::U8 | MemWidth::I8 => "i8",
        MemWidth::U16 | MemWidth::I16 => "i16",
        MemWidth::U32 | MemWidth::I32 => "i32",
        MemWidth::U64 => "i64",
    };

    if store_ty != "i64" {
        let trunc = next_tmp(tmp);
        writeln!(out, "  {} = trunc i64 {} to {}", trunc, val, store_ty).unwrap();
        writeln!(out, "  store {} {}, ptr {}", store_ty, trunc, ptr).unwrap();
    } else {
        writeln!(out, "  store i64 {}, ptr {}", val, ptr).unwrap();
    }
}

/// Emit an indirect jump as a switch statement over the jump table.
fn emit_indirect_jump(
    out: &mut String,
    reg_val: &str,
    program: &DecodedProgram,
    func_block_pcs: &HashSet<usize>,
    tmp: &mut u64,
) {
    let trunc = next_tmp(tmp);
    let sw_default = next_label("sw_default", tmp);
    writeln!(out, "  {} = trunc i64 {} to i32", trunc, reg_val).unwrap();

    // Build switch over jump table entries
    write!(out, "  switch i32 {}, label %{} [", trunc, sw_default).unwrap();

    for (idx, &target_pc) in program.jump_table.iter().enumerate() {
        let target = target_pc as usize;
        if func_block_pcs.contains(&target) {
            write!(out, " i32 {}, label %bb_{:04x}", idx, target).unwrap();
        }
    }
    writeln!(out, " ]").unwrap();

    // Default case: return
    writeln!(out, "\n{}:", sw_default).unwrap();
    let t = next_tmp(tmp);
    writeln!(out, "  {} = load i64, ptr %r0, align 8", t).unwrap();
    writeln!(out, "  ret i64 {}", t).unwrap();
}

/// Convert PVM branch condition string to LLVM icmp predicate.
fn branch_cond_to_icmp(cond: &str) -> &'static str {
    match cond {
        "eq" => "eq",
        "ne" => "ne",
        "lt_u" => "ult",
        "lt_s" => "slt",
        "ge_u" => "uge",
        "ge_s" => "sge",
        "gt_u" => "ugt",
        "gt_s" => "sgt",
        "le_u" => "ule",
        "le_s" => "sle",
        _ => "eq", // Fallback
    }
}

/// Generate next temporary variable name.
fn next_tmp(counter: &mut u64) -> String {
    let name = format!("%t{}", counter);
    *counter += 1;
    name
}

/// Generate a unique block label name.
fn next_label(prefix: &str, counter: &mut u64) -> String {
    let name = format!("{}_{}", prefix, counter);
    *counter += 1;
    name
}

/// Sanitize a name for use as an LLVM identifier.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BasicBlock, ControlFlowGraph, build_test_cfg};
    use crate::decoder::DecodedProgram;
    use crate::functions::Function;
    use std::collections::HashSet;
    use wasm_pvm::pvm::Instruction;

    fn test_program(memory_base: Option<u64>) -> DecodedProgram {
        DecodedProgram {
            jump_table: vec![],
            instructions: vec![],
            code_len: 0,
            memory_base,
        }
    }

    fn single_function(entry_pc: usize, block_pcs: &[usize]) -> Function {
        Function {
            name: "main".to_string(),
            entry_pc,
            block_pcs: block_pcs.iter().copied().collect(),
        }
    }

    #[test]
    fn emit_indirect_jump_uses_unique_default_labels() {
        let program = DecodedProgram {
            jump_table: vec![0x10, 0x20],
            instructions: vec![],
            code_len: 0,
            memory_base: None,
        };
        let func_block_pcs: HashSet<usize> = [0x10usize, 0x20usize].into_iter().collect();

        let mut out = String::new();
        let mut tmp = 0;

        emit_indirect_jump(&mut out, "%r1", &program, &func_block_pcs, &mut tmp);
        emit_indirect_jump(&mut out, "%r2", &program, &func_block_pcs, &mut tmp);

        let mut labels: Vec<String> = out
            .lines()
            .filter_map(|line| line.strip_suffix(':'))
            .filter(|line| line.starts_with("sw_default_"))
            .map(|line| line.to_string())
            .collect();
        labels.sort();
        labels.dedup();

        assert_eq!(labels.len(), 2, "expected unique labels, got:\n{out}");
        for label in labels {
            assert_eq!(
                out.matches(&format!("label %{}", label)).count(),
                1,
                "switch should reference each default label once"
            );
            assert_eq!(
                out.matches(&format!("{}:", label)).count(),
                1,
                "each default label should be emitted once"
            );
        }
    }

    #[test]
    fn lift_program_initializes_sp_in_r1() {
        let program = test_program(Some(0x50000));
        let cfg = build_test_cfg(0, vec![(0, vec![(0, Instruction::Trap)], vec![])]);
        let func = single_function(0, &[0]);

        let ir = lift_program(&program, &cfg, &[func]);

        assert!(
            ir.contains("store i64 327680, ptr %r1, align 8 ; SP = memory_base"),
            "SP must be initialized in r1: {ir}"
        );
        assert!(
            !ir.contains("ptr %r2, align 8 ; SP = memory_base"),
            "SP must not be initialized in r2: {ir}"
        );
    }

    #[test]
    fn unknown_opcode_emits_single_terminator() {
        let program = test_program(None);
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![(
                    0,
                    Instruction::Unknown {
                        opcode: 0xAB,
                        raw_bytes: vec![0xAB, 0x00],
                    },
                )],
                vec![],
            )],
        );
        let func = single_function(0, &[0]);

        let ir = lift_program(&program, &cfg, &[func]);

        assert_eq!(
            ir.matches("call void @pvm_trap()").count(),
            1,
            "unknown opcode block should trap exactly once: {ir}"
        );
        assert_eq!(
            ir.matches("unreachable").count(),
            1,
            "unknown opcode block should emit a single unreachable terminator: {ir}"
        );
        assert!(
            !ir.contains("ret i64"),
            "unknown opcode block must not emit an additional return terminator: {ir}"
        );
    }

    #[test]
    fn external_branch_exit_labels_are_emitted_once() {
        let program = test_program(None);
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::BranchEqImm {
                            reg: 0,
                            value: 0,
                            offset: 0x200,
                        },
                    )],
                    vec![],
                ),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchEqImm {
                            reg: 0,
                            value: 1,
                            offset: 0x1F6, // 10 + 0x1F6 = 0x200
                        },
                    )],
                    vec![],
                ),
            ],
        );
        let func = single_function(0, &[0, 10]);

        let ir = lift_program(&program, &cfg, &[func]);

        assert_eq!(
            ir.matches("bb_exit_0200:").count(),
            1,
            "duplicate external exit labels must be deduplicated: {ir}"
        );
    }

    #[test]
    fn empty_block_with_external_successor_returns_r0() {
        let program = test_program(None);
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(BasicBlock {
            start_pc: 0,
            end_pc: 0,
            instructions: vec![],
            successors: vec![0x200],
            predecessors: vec![],
        });
        let func = single_function(0, &[0]);

        let ir = lift_program(&program, &cfg, &[func]);

        assert!(
            !ir.contains("br label %bb_0200"),
            "empty block should not branch to undefined in-function label: {ir}"
        );
        assert!(
            ir.contains("ret i64"),
            "empty block with external successor should fallback to return: {ir}"
        );
    }
}
