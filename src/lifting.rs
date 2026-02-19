//! Register Lifting - Variable Recovery & Expression Simplification
//!
//! Transforms raw register-based pseudo-code into higher-level variable-based
//! representations by:
//! - Assigning meaningful variable names based on register usage patterns
//! - Propagating constants inline where beneficial
//! - Folding single-use expression chains into compound expressions

use crate::cfg::ControlFlowGraph;
use crate::dataflow::DataFlowAnalysis;
use std::collections::{HashMap, HashSet};
use wasm_pvm::pvm::Instruction;

/// Inferred variable type based on usage context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    Integer,
    Pointer,
    Boolean,
}

/// A recovered high-level variable corresponding to a single register definition.
#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub var_type: VarType,
}

/// An expression tree representing a computation.
#[derive(Debug, Clone)]
pub enum Expression {
    Const(i64),
    Var(String),
    BinOp {
        op: String,
        lhs: Box<Expression>,
        rhs: Box<Expression>,
    },
    UnaryOp {
        op: String,
        operand: Box<Expression>,
    },
    Load {
        width: String,
        base: Box<Expression>,
        offset: i32,
    },
    Store {
        width: String,
        base: Box<Expression>,
        offset: i32,
        value: Box<Expression>,
    },
    Call {
        name: String,
        args: Vec<Expression>,
    },
    /// A branch/jump/trap that doesn't produce a value - kept as raw text.
    Raw(String),
}

/// Result of the lifting pass: variables, expressions, and eliminated PCs.
#[derive(Debug)]
pub struct LiftedProgram {
    /// Variable assigned to each (def_pc, reg) pair.
    pub variables: HashMap<(usize, u8), Variable>,
    /// Lifted expression for each PC.
    pub expressions: HashMap<usize, Expression>,
    /// PCs that have been folded into other expressions and should be skipped.
    pub eliminated_pcs: HashSet<usize>,
    /// Variable name to use for each (pc, reg) use-site, accounting for reaching definitions.
    pub var_at_use: HashMap<(usize, u8), String>,
}

impl LiftedProgram {
    /// Run the full lifting pipeline on a CFG with dataflow information.
    pub fn analyze(cfg: &ControlFlowGraph, dataflow: &DataFlowAnalysis) -> Self {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
        };

        lifted.assign_variables(cfg, dataflow);
        lifted.build_expressions(cfg);
        lifted.propagate_constants();
        lifted.simplify_all_expressions();
        lifted.fold_expressions(cfg);
        lifted.simplify_all_expressions();

        lifted
    }

    /// Assign variable names to each register definition based on type inference.
    fn assign_variables(&mut self, cfg: &ControlFlowGraph, dataflow: &DataFlowAnalysis) {
        let mut var_counter: usize = 0;
        let mut ptr_counter: usize = 0;
        let mut cond_counter: usize = 0;

        // Collect all definitions in PC order for deterministic naming.
        let mut all_defs: Vec<(usize, u8)> = Vec::new();
        let mut sorted_blocks: Vec<usize> = cfg.blocks.keys().copied().collect();
        sorted_blocks.sort();

        for &block_pc in &sorted_blocks {
            if let Some(block) = cfg.blocks.get(&block_pc) {
                for (pc, _instr) in &block.instructions {
                    if let Some(defs) = dataflow.defs_at_pc.get(pc) {
                        for &reg in defs {
                            all_defs.push((*pc, reg));
                        }
                    }
                }
            }
        }

        // Infer types and assign names.
        for &(def_pc, reg) in &all_defs {
            let var_type = self.infer_type(def_pc, reg, cfg, dataflow);
            let name = match var_type {
                VarType::Pointer => {
                    let name = format!("ptr_{}", ptr_counter);
                    ptr_counter += 1;
                    name
                }
                VarType::Boolean => {
                    let name = format!("cond_{}", cond_counter);
                    cond_counter += 1;
                    name
                }
                _ => {
                    let name = format!("var_{}", var_counter);
                    var_counter += 1;
                    name
                }
            };

            let variable = Variable {
                name: name.clone(),
                var_type,
            };
            self.variables.insert((def_pc, reg), variable);
        }

        // Build use-site mapping: for each use of a register at a PC, find which
        // definition's variable name to use.
        for chains in dataflow.chains.values() {
            for chain in chains {
                if let Some(var) = self
                    .variables
                    .get(&(chain.definition.pc, chain.definition.reg))
                {
                    let name = var.name.clone();
                    for u in &chain.uses {
                        self.var_at_use.insert((u.pc, u.reg), name.clone());
                    }
                }
            }
        }
    }

    /// Infer the type of a variable from how it is used.
    fn infer_type(
        &self,
        def_pc: usize,
        reg: u8,
        cfg: &ControlFlowGraph,
        dataflow: &DataFlowAnalysis,
    ) -> VarType {
        // Check the defining instruction itself.
        if let Some(instr) = Self::instruction_at(cfg, def_pc) {
            match instr {
                Instruction::SetLtU { .. }
                | Instruction::SetLtS { .. }
                | Instruction::SetLtUImm { .. }
                | Instruction::SetLtSImm { .. } => return VarType::Boolean,
                Instruction::Sbrk { .. } => return VarType::Pointer,
                _ => {}
            }
        }

        // Check uses: if used as base in a load/store, it's a pointer.
        for chains in dataflow.chains.values() {
            for chain in chains {
                if chain.definition.pc == def_pc && chain.definition.reg == reg {
                    for u in &chain.uses {
                        if let Some(use_instr) = Self::instruction_at(cfg, u.pc)
                            && Self::is_used_as_base(use_instr, reg)
                        {
                            return VarType::Pointer;
                        }
                    }
                }
            }
        }

        VarType::Integer
    }

    /// Check if a register is used as the base address in a load/store instruction.
    fn is_used_as_base(instr: &Instruction, reg: u8) -> bool {
        match instr {
            Instruction::LoadIndU8 { base, .. }
            | Instruction::LoadIndI8 { base, .. }
            | Instruction::LoadIndU16 { base, .. }
            | Instruction::LoadIndI16 { base, .. }
            | Instruction::LoadIndU32 { base, .. }
            | Instruction::LoadIndU64 { base, .. } => *base == reg,
            Instruction::StoreIndU8 { base, .. }
            | Instruction::StoreIndU16 { base, .. }
            | Instruction::StoreIndU32 { base, .. }
            | Instruction::StoreIndU64 { base, .. } => *base == reg,
            _ => false,
        }
    }

    /// Look up the instruction at a given PC across all blocks.
    fn instruction_at(cfg: &ControlFlowGraph, pc: usize) -> Option<&Instruction> {
        for block in cfg.blocks.values() {
            for (ipc, instr) in &block.instructions {
                if *ipc == pc {
                    return Some(instr);
                }
            }
        }
        None
    }

    /// Build an Expression for every instruction PC.
    fn build_expressions(&mut self, cfg: &ControlFlowGraph) {
        let mut sorted_blocks: Vec<usize> = cfg.blocks.keys().copied().collect();
        sorted_blocks.sort();

        for &block_pc in &sorted_blocks {
            if let Some(block) = cfg.blocks.get(&block_pc) {
                for (pc, instr) in &block.instructions {
                    let expr = self.instruction_to_expression(*pc, instr);
                    self.expressions.insert(*pc, expr);
                }
            }
        }
    }

    /// Convert a single instruction into an Expression, using variable names.
    fn instruction_to_expression(&self, pc: usize, instr: &Instruction) -> Expression {
        match instr {
            Instruction::LoadImm { value, .. } => Expression::Const(*value as i64),
            Instruction::LoadImm64 { value, .. } => Expression::Const(*value as i64),

            // Three-register binary ops
            Instruction::Add32 { src1, src2, .. } => self.make_binop(pc, "+", *src1, *src2),
            Instruction::Sub32 { src1, src2, .. } => self.make_binop(pc, "-", *src1, *src2),
            Instruction::Mul32 { src1, src2, .. } => self.make_binop(pc, "*", *src1, *src2),
            Instruction::DivU32 { src1, src2, .. } => self.make_binop(pc, "/u", *src1, *src2),
            Instruction::DivS32 { src1, src2, .. } => self.make_binop(pc, "/s", *src1, *src2),
            Instruction::RemU32 { src1, src2, .. } => self.make_binop(pc, "%u", *src1, *src2),
            Instruction::RemS32 { src1, src2, .. } => self.make_binop(pc, "%s", *src1, *src2),
            Instruction::ShloL32 { src1, src2, .. } => self.make_binop(pc, "<<", *src1, *src2),
            Instruction::ShloR32 { src1, src2, .. } => self.make_binop(pc, ">>u", *src1, *src2),
            Instruction::SharR32 { src1, src2, .. } => self.make_binop(pc, ">>s", *src1, *src2),
            Instruction::Add64 { src1, src2, .. } => self.make_binop(pc, "+", *src1, *src2),
            Instruction::Sub64 { src1, src2, .. } => self.make_binop(pc, "-", *src1, *src2),
            Instruction::Mul64 { src1, src2, .. } => self.make_binop(pc, "*", *src1, *src2),
            Instruction::DivU64 { src1, src2, .. } => self.make_binop(pc, "/u", *src1, *src2),
            Instruction::DivS64 { src1, src2, .. } => self.make_binop(pc, "/s", *src1, *src2),
            Instruction::RemU64 { src1, src2, .. } => self.make_binop(pc, "%u", *src1, *src2),
            Instruction::RemS64 { src1, src2, .. } => self.make_binop(pc, "%s", *src1, *src2),
            Instruction::ShloL64 { src1, src2, .. } => self.make_binop(pc, "<<", *src1, *src2),
            Instruction::ShloR64 { src1, src2, .. } => self.make_binop(pc, ">>u", *src1, *src2),
            Instruction::SharR64 { src1, src2, .. } => self.make_binop(pc, ">>s", *src1, *src2),
            Instruction::And { src1, src2, .. } => self.make_binop(pc, "&", *src1, *src2),
            Instruction::Or { src1, src2, .. } => self.make_binop(pc, "|", *src1, *src2),
            Instruction::Xor { src1, src2, .. } => self.make_binop(pc, "^", *src1, *src2),
            Instruction::SetLtU { src1, src2, .. } => self.make_binop(pc, "<u", *src1, *src2),
            Instruction::SetLtS { src1, src2, .. } => self.make_binop(pc, "<s", *src1, *src2),

            // Register + immediate ops
            Instruction::AddImm32 { src, value, .. } => {
                self.make_binop_imm(pc, "+", *src, *value as i64)
            }
            Instruction::AddImm64 { src, value, .. } => {
                self.make_binop_imm(pc, "+", *src, *value as i64)
            }
            Instruction::SetLtUImm { src, value, .. } => {
                self.make_binop_imm(pc, "<u", *src, *value as i64)
            }
            Instruction::SetLtSImm { src, value, .. } => {
                self.make_binop_imm(pc, "<s", *src, *value as i64)
            }

            // Unary ops
            Instruction::CountSetBits64 { src, .. } => self.make_unary(pc, "popcnt64", *src),
            Instruction::CountSetBits32 { src, .. } => self.make_unary(pc, "popcnt32", *src),
            Instruction::LeadingZeroBits64 { src, .. } => self.make_unary(pc, "clz64", *src),
            Instruction::LeadingZeroBits32 { src, .. } => self.make_unary(pc, "clz32", *src),
            Instruction::TrailingZeroBits64 { src, .. } => self.make_unary(pc, "ctz64", *src),
            Instruction::TrailingZeroBits32 { src, .. } => self.make_unary(pc, "ctz32", *src),
            Instruction::SignExtend8 { src, .. } => self.make_unary(pc, "sext8", *src),
            Instruction::SignExtend16 { src, .. } => self.make_unary(pc, "sext16", *src),
            Instruction::ZeroExtend16 { src, .. } => self.make_unary(pc, "zext16", *src),
            Instruction::Sbrk { src, .. } => self.make_unary(pc, "sbrk", *src),

            // Load instructions
            Instruction::LoadIndU8 { base, offset, .. } => self.make_load(pc, "u8", *base, *offset),
            Instruction::LoadIndI8 { base, offset, .. } => self.make_load(pc, "i8", *base, *offset),
            Instruction::LoadIndU16 { base, offset, .. } => {
                self.make_load(pc, "u16", *base, *offset)
            }
            Instruction::LoadIndI16 { base, offset, .. } => {
                self.make_load(pc, "i16", *base, *offset)
            }
            Instruction::LoadIndU32 { base, offset, .. } => {
                self.make_load(pc, "u32", *base, *offset)
            }
            Instruction::LoadIndU64 { base, offset, .. } => {
                self.make_load(pc, "u64", *base, *offset)
            }

            // Store instructions
            Instruction::StoreIndU8 {
                base, src, offset, ..
            } => self.make_store(pc, "u8", *base, *offset, *src),
            Instruction::StoreIndU16 {
                base, src, offset, ..
            } => self.make_store(pc, "u16", *base, *offset, *src),
            Instruction::StoreIndU32 {
                base, src, offset, ..
            } => self.make_store(pc, "u32", *base, *offset, *src),
            Instruction::StoreIndU64 {
                base, src, offset, ..
            } => self.make_store(pc, "u64", *base, *offset, *src),

            // Ecalli
            Instruction::Ecalli { index } => Expression::Call {
                name: "ecalli".to_string(),
                args: vec![Expression::Const(*index as i64)],
            },

            // Control flow - kept as raw text
            Instruction::Trap => Expression::Raw("trap".to_string()),
            Instruction::Fallthrough => Expression::Raw("fallthrough".to_string()),
            Instruction::Jump { offset } => Expression::Raw(format!("jump {}", offset)),
            Instruction::JumpInd { reg, .. } => {
                Expression::Raw(format!("jump_ind {}", self.reg_name(pc, *reg)))
            }
            Instruction::BranchEqImm { reg, value, offset } => Expression::Raw(format!(
                "if ({} == {}) jump {}",
                self.reg_name(pc, *reg),
                value,
                offset
            )),
            Instruction::BranchNeImm { reg, value, offset } => Expression::Raw(format!(
                "if ({} != {}) jump {}",
                self.reg_name(pc, *reg),
                value,
                offset
            )),
            Instruction::BranchGeSImm { reg, value, offset } => Expression::Raw(format!(
                "if ({} >=s {}) jump {}",
                self.reg_name(pc, *reg),
                value,
                offset
            )),
            Instruction::BranchGeU {
                reg1, reg2, offset, ..
            } => Expression::Raw(format!(
                "if ({} >=u {}) jump {}",
                self.reg_name(pc, *reg1),
                self.reg_name(pc, *reg2),
                offset
            )),
            Instruction::BranchLtU {
                reg1, reg2, offset, ..
            } => Expression::Raw(format!(
                "if ({} <u {}) jump {}",
                self.reg_name(pc, *reg1),
                self.reg_name(pc, *reg2),
                offset
            )),
        }
    }

    /// Get the variable name for a register used at a given PC, falling back to rN.
    fn reg_name(&self, use_pc: usize, reg: u8) -> String {
        self.var_at_use
            .get(&(use_pc, reg))
            .cloned()
            .unwrap_or_else(|| format!("r{}", reg))
    }

    fn make_binop(&self, pc: usize, op: &str, src1: u8, src2: u8) -> Expression {
        Expression::BinOp {
            op: op.to_string(),
            lhs: Box::new(Expression::Var(self.reg_name(pc, src1))),
            rhs: Box::new(Expression::Var(self.reg_name(pc, src2))),
        }
    }

    fn make_binop_imm(&self, pc: usize, op: &str, src: u8, value: i64) -> Expression {
        Expression::BinOp {
            op: op.to_string(),
            lhs: Box::new(Expression::Var(self.reg_name(pc, src))),
            rhs: Box::new(Expression::Const(value)),
        }
    }

    fn make_unary(&self, pc: usize, op: &str, src: u8) -> Expression {
        Expression::UnaryOp {
            op: op.to_string(),
            operand: Box::new(Expression::Var(self.reg_name(pc, src))),
        }
    }

    fn make_load(&self, pc: usize, width: &str, base: u8, offset: i32) -> Expression {
        Expression::Load {
            width: width.to_string(),
            base: Box::new(Expression::Var(self.reg_name(pc, base))),
            offset,
        }
    }

    fn make_store(&self, pc: usize, width: &str, base: u8, offset: i32, src: u8) -> Expression {
        Expression::Store {
            width: width.to_string(),
            base: Box::new(Expression::Var(self.reg_name(pc, base))),
            offset,
            value: Box::new(Expression::Var(self.reg_name(pc, src))),
        }
    }

    /// Propagate constants: if a definition is LoadImm with a single use,
    /// replace the variable reference in the use-expression with the constant.
    fn propagate_constants(&mut self) {
        // Collect single-use constant definitions: (def_pc, reg, value).
        let mut const_defs: Vec<(usize, u8, i64)> = Vec::new();
        for (&(def_pc, reg), var) in &self.variables {
            if let Some(Expression::Const(value)) = self.expressions.get(&def_pc) {
                // Count how many uses reference this variable name.
                let use_count = self
                    .var_at_use
                    .values()
                    .filter(|name| **name == var.name)
                    .count();
                if use_count == 1 {
                    const_defs.push((def_pc, reg, *value));
                }
            }
        }

        // For each single-use constant, substitute inline.
        for (def_pc, reg, value) in &const_defs {
            let var = match self.variables.get(&(*def_pc, *reg)) {
                Some(v) => v.name.clone(),
                None => continue,
            };

            // Replace Var(name) with Const(value) in all expressions.
            let pcs: Vec<usize> = self.expressions.keys().copied().collect();
            for pc in pcs {
                if let Some(expr) = self.expressions.remove(&pc) {
                    let new_expr = substitute_var(&expr, &var, &Expression::Const(*value));
                    self.expressions.insert(pc, new_expr);
                }
            }

            // Mark the constant definition PC as eliminated.
            self.eliminated_pcs.insert(*def_pc);
        }
    }

    /// Fold expressions: when a definition has exactly one use in the immediately
    /// following instruction within the same block, inline the expression.
    fn fold_expressions(&mut self, cfg: &ControlFlowGraph) {
        // Build a map of (pc -> next_pc) within each block.
        let mut next_in_block: HashMap<usize, usize> = HashMap::new();
        for block in cfg.blocks.values() {
            for i in 0..block.instructions.len().saturating_sub(1) {
                let cur_pc = block.instructions[i].0;
                let next_pc = block.instructions[i + 1].0;
                next_in_block.insert(cur_pc, next_pc);
            }
        }

        // Iterate until no more folding possible.
        let mut changed = true;
        while changed {
            changed = false;

            // Collect candidates: (def_pc, var_name, next_pc) where the def has
            // exactly one use at next_pc.
            let mut candidates: Vec<(usize, String, usize)> = Vec::new();

            for (&(def_pc, _reg), var) in &self.variables {
                // Skip already eliminated.
                if self.eliminated_pcs.contains(&def_pc) {
                    continue;
                }

                // Must have a next instruction in the same block.
                let next_pc = match next_in_block.get(&def_pc) {
                    Some(&n) => n,
                    None => continue,
                };

                // The definition's expression must exist and not be Raw/Store.
                let def_expr = match self.expressions.get(&def_pc) {
                    Some(e) => e,
                    None => continue,
                };
                if matches!(def_expr, Expression::Raw(_) | Expression::Store { .. }) {
                    continue;
                }

                // Count uses of this variable name.
                let use_count = self
                    .var_at_use
                    .values()
                    .filter(|name| **name == var.name)
                    .count();
                if use_count != 1 {
                    continue;
                }

                // The single use must be at next_pc.
                let is_at_next = self
                    .var_at_use
                    .iter()
                    .any(|(&(upc, _), name)| *name == var.name && upc == next_pc);
                if !is_at_next {
                    continue;
                }

                // Check depth limit.
                if expression_depth(def_expr) >= 3 {
                    continue;
                }

                candidates.push((def_pc, var.name.clone(), next_pc));
            }

            for (def_pc, var_name, next_pc) in candidates {
                let def_expr = match self.expressions.get(&def_pc) {
                    Some(e) => e.clone(),
                    None => continue,
                };

                if let Some(use_expr) = self.expressions.remove(&next_pc) {
                    let folded = substitute_var(&use_expr, &var_name, &def_expr);
                    self.expressions.insert(next_pc, folded);
                    self.eliminated_pcs.insert(def_pc);
                    changed = true;
                }
            }
        }
    }

    /// Simplify all expressions in the program by folding identity operations.
    fn simplify_all_expressions(&mut self) {
        let pcs: Vec<usize> = self.expressions.keys().copied().collect();
        for pc in pcs {
            if let Some(expr) = self.expressions.remove(&pc) {
                self.expressions.insert(pc, simplify_expression(expr));
            }
        }
    }

    /// Produce a summary of the lifting results.
    pub fn summarize(&self) -> String {
        use std::fmt::Write;
        let mut output = String::new();
        output.push_str("=== Register Lifting ===\n\n");

        let _ = writeln!(
            output,
            "Variables: {}, Eliminated instructions: {}",
            self.variables.len(),
            self.eliminated_pcs.len()
        );

        // Sort by key for deterministic output.
        let mut vars: Vec<_> = self.variables.iter().collect();
        vars.sort_by_key(|&(&(pc, reg), _)| (pc, reg));

        for &(&(pc, reg), var) in &vars {
            let type_str = match var.var_type {
                VarType::Integer => "int",
                VarType::Pointer => "ptr",
                VarType::Boolean => "bool",
            };
            let _ = writeln!(
                output,
                "  {} : {} (r{} @ {:#06x})",
                var.name, type_str, reg, pc
            );
        }

        output
    }

    /// Format an instruction at a given PC as a lifted pseudo-code line.
    /// Returns None if the PC has been eliminated.
    pub fn format_pc(&self, pc: usize, instr: &Instruction) -> Option<String> {
        if self.eliminated_pcs.contains(&pc) {
            return None;
        }

        let expr = self.expressions.get(&pc)?;

        // Determine if this instruction defines a register.
        let dst_name = self.def_var_name(pc, instr);

        match expr {
            Expression::Raw(s) => Some(s.clone()),
            Expression::Store {
                width,
                base,
                offset,
                value,
            } => Some(format!(
                "{}[{} + {}] = {}",
                width,
                format_expression(base),
                offset,
                format_expression(value)
            )),
            Expression::Call { name, args } => {
                let arg_strs: Vec<String> = args.iter().map(format_expression).collect();
                if let Some(dst) = dst_name {
                    Some(format!("{} = {}({})", dst, name, arg_strs.join(", ")))
                } else {
                    Some(format!("{}({})", name, arg_strs.join(", ")))
                }
            }
            _ => {
                if let Some(dst) = dst_name {
                    Some(format!("{} = {}", dst, format_expression(expr)))
                } else {
                    Some(format_expression(expr))
                }
            }
        }
    }

    /// Get the variable name for the destination register defined at a PC.
    fn def_var_name(&self, pc: usize, instr: &Instruction) -> Option<String> {
        let reg = match instr {
            Instruction::LoadImm { reg, .. } | Instruction::LoadImm64 { reg, .. } => Some(*reg),
            Instruction::Add32 { dst, .. }
            | Instruction::Sub32 { dst, .. }
            | Instruction::Mul32 { dst, .. }
            | Instruction::DivU32 { dst, .. }
            | Instruction::DivS32 { dst, .. }
            | Instruction::RemU32 { dst, .. }
            | Instruction::RemS32 { dst, .. }
            | Instruction::ShloL32 { dst, .. }
            | Instruction::ShloR32 { dst, .. }
            | Instruction::SharR32 { dst, .. }
            | Instruction::Add64 { dst, .. }
            | Instruction::Sub64 { dst, .. }
            | Instruction::Mul64 { dst, .. }
            | Instruction::DivU64 { dst, .. }
            | Instruction::DivS64 { dst, .. }
            | Instruction::RemU64 { dst, .. }
            | Instruction::RemS64 { dst, .. }
            | Instruction::ShloL64 { dst, .. }
            | Instruction::ShloR64 { dst, .. }
            | Instruction::SharR64 { dst, .. }
            | Instruction::And { dst, .. }
            | Instruction::Or { dst, .. }
            | Instruction::Xor { dst, .. }
            | Instruction::SetLtU { dst, .. }
            | Instruction::SetLtS { dst, .. }
            | Instruction::AddImm32 { dst, .. }
            | Instruction::AddImm64 { dst, .. }
            | Instruction::SetLtUImm { dst, .. }
            | Instruction::SetLtSImm { dst, .. }
            | Instruction::Sbrk { dst, .. }
            | Instruction::CountSetBits64 { dst, .. }
            | Instruction::CountSetBits32 { dst, .. }
            | Instruction::LeadingZeroBits64 { dst, .. }
            | Instruction::LeadingZeroBits32 { dst, .. }
            | Instruction::TrailingZeroBits64 { dst, .. }
            | Instruction::TrailingZeroBits32 { dst, .. }
            | Instruction::SignExtend8 { dst, .. }
            | Instruction::SignExtend16 { dst, .. }
            | Instruction::ZeroExtend16 { dst, .. }
            | Instruction::LoadIndU8 { dst, .. }
            | Instruction::LoadIndI8 { dst, .. }
            | Instruction::LoadIndU16 { dst, .. }
            | Instruction::LoadIndI16 { dst, .. }
            | Instruction::LoadIndU32 { dst, .. }
            | Instruction::LoadIndU64 { dst, .. } => Some(*dst),
            _ => None,
        };

        reg.and_then(|r| self.variables.get(&(pc, r)).map(|v| v.name.clone()))
    }
}

/// Recursively simplify an expression by folding identity operations.
/// - `x + 0`, `x - 0`, `x | 0`, `x ^ 0`, `x << 0`, `x >>u 0`, `x >>s 0` → `x`
/// - `x * 1`, `x /u 1`, `x /s 1` → `x`
/// - `x * 0`, `x & 0` → `0`
/// - `bool <u 1` → `!bool` (common negation pattern)
fn simplify_expression(expr: Expression) -> Expression {
    match expr {
        Expression::BinOp { op, lhs, rhs } => {
            let lhs = simplify_expression(*lhs);
            let rhs = simplify_expression(*rhs);

            match (&op[..], &lhs, &rhs) {
                // x + 0, x - 0, x | 0, x ^ 0, x << 0, x >>u 0, x >>s 0 → x
                ("+" | "-" | "|" | "^" | "<<" | ">>u" | ">>s", _, Expression::Const(0)) => lhs,
                // 0 + x, 0 | x, 0 ^ x → x (commutative identities)
                ("+" | "|" | "^", Expression::Const(0), _) => rhs,
                // x * 1, x /u 1, x /s 1 → x
                ("*" | "/u" | "/s", _, Expression::Const(1)) => lhs,
                // 1 * x → x
                ("*", Expression::Const(1), _) => rhs,
                // x * 0 → 0, x & 0 → 0
                ("*" | "&", _, Expression::Const(0)) => Expression::Const(0),
                // 0 * x → 0, 0 & x → 0
                ("*" | "&", Expression::Const(0), _) => Expression::Const(0),
                // bool <u 1 → !bool (negation pattern from SetLtUImm { value: 1 })
                ("<u", _, Expression::Const(1)) => Expression::UnaryOp {
                    op: "!".to_string(),
                    operand: Box::new(lhs),
                },
                _ => Expression::BinOp {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
            }
        }
        Expression::UnaryOp { op, operand } => Expression::UnaryOp {
            op,
            operand: Box::new(simplify_expression(*operand)),
        },
        Expression::Load {
            width,
            base,
            offset,
        } => Expression::Load {
            width,
            base: Box::new(simplify_expression(*base)),
            offset,
        },
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => Expression::Store {
            width,
            base: Box::new(simplify_expression(*base)),
            offset,
            value: Box::new(simplify_expression(*value)),
        },
        Expression::Call { name, args } => Expression::Call {
            name,
            args: args.into_iter().map(simplify_expression).collect(),
        },
        other => other,
    }
}

/// Recursively substitute all `Var(name)` nodes with a replacement expression.
fn substitute_var(expr: &Expression, name: &str, replacement: &Expression) -> Expression {
    match expr {
        Expression::Var(n) if n == name => replacement.clone(),
        Expression::Var(_) | Expression::Const(_) | Expression::Raw(_) => expr.clone(),
        Expression::BinOp { op, lhs, rhs } => Expression::BinOp {
            op: op.clone(),
            lhs: Box::new(substitute_var(lhs, name, replacement)),
            rhs: Box::new(substitute_var(rhs, name, replacement)),
        },
        Expression::UnaryOp { op, operand } => Expression::UnaryOp {
            op: op.clone(),
            operand: Box::new(substitute_var(operand, name, replacement)),
        },
        Expression::Load {
            width,
            base,
            offset,
        } => Expression::Load {
            width: width.clone(),
            base: Box::new(substitute_var(base, name, replacement)),
            offset: *offset,
        },
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => Expression::Store {
            width: width.clone(),
            base: Box::new(substitute_var(base, name, replacement)),
            offset: *offset,
            value: Box::new(substitute_var(value, name, replacement)),
        },
        Expression::Call {
            name: fn_name,
            args,
        } => Expression::Call {
            name: fn_name.clone(),
            args: args
                .iter()
                .map(|a| substitute_var(a, name, replacement))
                .collect(),
        },
    }
}

/// Compute the depth of an expression tree.
fn expression_depth(expr: &Expression) -> usize {
    match expr {
        Expression::Const(_) | Expression::Var(_) | Expression::Raw(_) => 0,
        Expression::BinOp { lhs, rhs, .. } => 1 + expression_depth(lhs).max(expression_depth(rhs)),
        Expression::UnaryOp { operand, .. } => 1 + expression_depth(operand),
        Expression::Load { base, .. } => 1 + expression_depth(base),
        Expression::Store { base, value, .. } => {
            1 + expression_depth(base).max(expression_depth(value))
        }
        Expression::Call { args, .. } => 1 + args.iter().map(expression_depth).max().unwrap_or(0),
    }
}

/// Format an Expression tree as a human-readable string with minimal parentheses.
pub fn format_expression(expr: &Expression) -> String {
    match expr {
        Expression::Const(v) => format!("{}", v),
        Expression::Var(name) => name.clone(),
        Expression::Raw(s) => s.clone(),
        Expression::BinOp { op, lhs, rhs } => {
            let lhs_str = format_expression_maybe_parens(lhs, op, true);
            let rhs_str = format_expression_maybe_parens(rhs, op, false);
            format!("{} {} {}", lhs_str, op, rhs_str)
        }
        Expression::UnaryOp { op, operand } => {
            format!("{}({})", op, format_expression(operand))
        }
        Expression::Load {
            width,
            base,
            offset,
        } => {
            format!("{}[{} + {}]", width, format_expression(base), offset)
        }
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => {
            format!(
                "{}[{} + {}] = {}",
                width,
                format_expression(base),
                offset,
                format_expression(value)
            )
        }
        Expression::Call { name, args } => {
            let arg_strs: Vec<String> = args.iter().map(format_expression).collect();
            format!("{}({})", name, arg_strs.join(", "))
        }
    }
}

/// Format a sub-expression, adding parentheses only when needed for precedence.
fn format_expression_maybe_parens(expr: &Expression, parent_op: &str, _is_left: bool) -> String {
    match expr {
        Expression::BinOp { op, .. } => {
            let needs_parens = op_precedence(op) < op_precedence(parent_op);
            if needs_parens {
                format!("({})", format_expression(expr))
            } else {
                format_expression(expr)
            }
        }
        _ => format_expression(expr),
    }
}

/// Simple operator precedence (higher = binds tighter).
fn op_precedence(op: &str) -> u8 {
    match op {
        "|" => 1,
        "^" => 2,
        "&" => 3,
        "==" | "!=" | "<u" | "<s" | ">=u" | ">=s" => 4,
        "<<" | ">>u" | ">>s" => 5,
        "+" | "-" => 6,
        "*" | "/u" | "/s" | "%u" | "%s" => 7,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BasicBlock, ControlFlowGraph};
    use crate::dataflow::DataFlowAnalysis;

    /// Helper to build a CFG from a list of (start_pc, instructions, successors).
    fn build_test_cfg(
        entry: usize,
        blocks: Vec<(usize, Vec<(usize, Instruction)>, Vec<usize>)>,
    ) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new(entry);
        let mut all_blocks: Vec<BasicBlock> = Vec::new();

        for (start_pc, instructions, successors) in &blocks {
            let end_pc = instructions
                .last()
                .map(|(pc, _)| pc + 1)
                .unwrap_or(*start_pc);
            all_blocks.push(BasicBlock {
                start_pc: *start_pc,
                end_pc,
                instructions: instructions.clone(),
                successors: successors.clone(),
                predecessors: Vec::new(),
            });
        }

        let successor_map: Vec<(usize, Vec<usize>)> = all_blocks
            .iter()
            .map(|b| (b.start_pc, b.successors.clone()))
            .collect();
        for (src_pc, succs) in &successor_map {
            for &succ_pc in succs {
                if let Some(b) = all_blocks.iter_mut().find(|b| b.start_pc == succ_pc) {
                    b.predecessors.push(*src_pc);
                }
            }
        }

        for b in all_blocks {
            cfg.add_block(b);
        }
        cfg
    }

    #[test]
    fn test_variable_naming_simple() {
        // r0 = 42; r1 = r0 + 1
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 42 }),
                    (
                        4,
                        Instruction::AddImm32 {
                            dst: 1,
                            src: 0,
                            value: 1,
                        },
                    ),
                    (8, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // Should have variables for r0@PC0 and r1@PC4.
        assert!(lifted.variables.contains_key(&(0, 0)));
        assert!(lifted.variables.contains_key(&(4, 1)));

        // Names should start with var_ (integer type).
        assert!(lifted.variables[&(0, 0)].name.starts_with("var_"));
        assert!(lifted.variables[&(4, 1)].name.starts_with("var_"));
    }

    #[test]
    fn test_constant_propagation_single_use() {
        // r0 = 42; r1 = r0 + 1; trap
        // r0 has a single use at PC 4, so it should be propagated.
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 42 }),
                    (
                        4,
                        Instruction::AddImm32 {
                            dst: 1,
                            src: 0,
                            value: 1,
                        },
                    ),
                    (8, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // PC 0 should be eliminated (constant propagated).
        assert!(
            lifted.eliminated_pcs.contains(&0),
            "PC 0 should be eliminated after constant propagation"
        );

        // PC 4's expression should contain the constant 42 instead of var reference.
        let expr = lifted.expressions.get(&4).unwrap();
        let formatted = format_expression(expr);
        assert!(
            formatted.contains("42"),
            "Expression should contain inlined constant 42, got: {}",
            formatted
        );
    }

    #[test]
    fn test_expression_folding() {
        // r0 = 42; r1 = r0 + 1; r2 = r1 * 3; trap
        // r0 single-use -> propagated; r1 single-use at next instruction -> folded
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 42 }),
                    (
                        4,
                        Instruction::AddImm32 {
                            dst: 1,
                            src: 0,
                            value: 1,
                        },
                    ),
                    (
                        8,
                        Instruction::Mul32 {
                            dst: 2,
                            src1: 1,
                            src2: 1,
                        },
                    ),
                    (12, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // PC 0 and PC 4 should both be eliminated.
        assert!(lifted.eliminated_pcs.contains(&0));
        assert!(lifted.eliminated_pcs.contains(&4));

        // PC 8 should have the folded expression.
        let line = lifted
            .format_pc(
                8,
                &Instruction::Mul32 {
                    dst: 2,
                    src1: 1,
                    src2: 1,
                },
            )
            .unwrap();
        // Should contain the folded computation with constants.
        assert!(
            line.contains("*"),
            "Should contain multiplication, got: {}",
            line
        );
    }

    #[test]
    fn test_pointer_type_inference() {
        // r0 = 100; r1 = u32[r0 + 0]; trap
        // r0 is used as base in a load -> should be Pointer.
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 100 }),
                    (
                        4,
                        Instruction::LoadIndU32 {
                            dst: 1,
                            base: 0,
                            offset: 0,
                        },
                    ),
                    (8, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let var = lifted.variables.get(&(0, 0)).unwrap();
        assert_eq!(
            var.var_type,
            VarType::Pointer,
            "r0 used as load base should be Pointer"
        );
        assert!(
            var.name.starts_with("ptr_"),
            "Pointer variable should have ptr_ prefix, got: {}",
            var.name
        );
    }

    #[test]
    fn test_boolean_type_inference() {
        // r2 = r0 <u r1; trap
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::SetLtU {
                            dst: 2,
                            src1: 0,
                            src2: 1,
                        },
                    ),
                    (4, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let var = lifted.variables.get(&(0, 2)).unwrap();
        assert_eq!(var.var_type, VarType::Boolean);
        assert!(var.name.starts_with("cond_"));
    }

    #[test]
    fn test_simplify_add_zero() {
        let expr = Expression::BinOp {
            op: "+".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_xor_zero() {
        let expr = Expression::BinOp {
            op: "^".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_mul_one() {
        let expr = Expression::BinOp {
            op: "*".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_mul_zero() {
        let expr = Expression::BinOp {
            op: "*".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "0");
    }

    #[test]
    fn test_simplify_and_zero() {
        let expr = Expression::BinOp {
            op: "&".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "0");
    }

    #[test]
    fn test_simplify_ltu_1_negation() {
        let expr = Expression::BinOp {
            op: "<u".to_string(),
            lhs: Box::new(Expression::Var("cond_0".to_string())),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "!(cond_0)");
    }

    #[test]
    fn test_simplify_shift_zero() {
        let expr = Expression::BinOp {
            op: "<<".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_nested() {
        // (x + 0) * 1 → x
        let expr = Expression::BinOp {
            op: "*".to_string(),
            lhs: Box::new(Expression::BinOp {
                op: "+".to_string(),
                lhs: Box::new(Expression::Var("x".to_string())),
                rhs: Box::new(Expression::Const(0)),
            }),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_no_change() {
        let expr = Expression::BinOp {
            op: "+".to_string(),
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(5)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x + 5");
    }

    #[test]
    fn test_format_expression_precedence() {
        // (a + b) * c should parenthesize the addition
        let expr = Expression::BinOp {
            op: "*".to_string(),
            lhs: Box::new(Expression::BinOp {
                op: "+".to_string(),
                lhs: Box::new(Expression::Var("a".to_string())),
                rhs: Box::new(Expression::Var("b".to_string())),
            }),
            rhs: Box::new(Expression::Var("c".to_string())),
        };
        let formatted = format_expression(&expr);
        assert_eq!(formatted, "(a + b) * c");
    }

    #[test]
    fn test_format_expression_no_unnecessary_parens() {
        // a * b + c should NOT parenthesize the multiplication
        let expr = Expression::BinOp {
            op: "+".to_string(),
            lhs: Box::new(Expression::BinOp {
                op: "*".to_string(),
                lhs: Box::new(Expression::Var("a".to_string())),
                rhs: Box::new(Expression::Var("b".to_string())),
            }),
            rhs: Box::new(Expression::Var("c".to_string())),
        };
        let formatted = format_expression(&expr);
        assert_eq!(formatted, "a * b + c");
    }

    #[test]
    fn test_no_fold_across_blocks() {
        // Block 0: r0 = 42
        // Block 10: r1 = r0 + 1; trap
        // r0 has single use but across blocks -> should NOT be folded (only propagated).
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::LoadImm { reg: 0, value: 42 })],
                    vec![10],
                ),
                (
                    10,
                    vec![
                        (
                            10,
                            Instruction::AddImm32 {
                                dst: 1,
                                src: 0,
                                value: 1,
                            },
                        ),
                        (14, Instruction::Trap),
                    ],
                    vec![],
                ),
            ],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // PC 0 should be eliminated (constant propagated since single use).
        assert!(lifted.eliminated_pcs.contains(&0));

        // PC 10 should NOT be eliminated.
        assert!(!lifted.eliminated_pcs.contains(&10));
    }
}
