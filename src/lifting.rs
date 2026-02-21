//! Register Lifting - Variable Recovery & Expression Simplification
//!
//! Transforms raw register-based pseudo-code into higher-level variable-based
//! representations by:
//! - Assigning meaningful variable names based on register usage patterns
//! - Propagating constants inline where beneficial
//! - Folding single-use expression chains into compound expressions

use crate::cfg::ControlFlowGraph;
use crate::dataflow::DataFlowAnalysis;
use crate::instruction::{BinOp, InstructionShape, MemWidth, UnaryOp};
use crate::structuring::DominatorTree;
use std::collections::{HashMap, HashSet};
use std::fmt;
use wasm_pvm::pvm::Instruction;

/// Inferred variable type based on usage context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    Integer,
    Pointer,
    Boolean,
}

impl fmt::Display for VarType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VarType::Integer => write!(f, "u64"),
            VarType::Pointer => write!(f, "ptr"),
            VarType::Boolean => write!(f, "bool"),
        }
    }
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
        op: BinOp,
        lhs: Box<Expression>,
        rhs: Box<Expression>,
    },
    UnaryOp {
        op: UnaryOp,
        operand: Box<Expression>,
    },
    Load {
        width: MemWidth,
        base: Box<Expression>,
        offset: i32,
    },
    Store {
        width: MemWidth,
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
    /// Tracks which variable names have already been declared with `let`.
    pub declared_vars: HashSet<String>,
    /// Named stack variables: maps (base_ptr_name, offset) to a stack variable name.
    pub stack_vars: HashMap<(String, i32), String>,
}

/// A set of variable declarations collected for a block, to be emitted at its top.
impl LiftedProgram {
    /// Run the full lifting pipeline on a CFG with dataflow information.
    pub fn analyze(cfg: &ControlFlowGraph, dataflow: &DataFlowAnalysis) -> Self {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
        };

        lifted.assign_variables(cfg, dataflow);
        lifted.build_expressions(cfg);
        lifted.propagate_constants();
        lifted.simplify_all_expressions();
        // Copy propagation and store-load forwarding BEFORE folding, so that
        // loads are replaced with stored values before they get inlined.
        lifted.propagate_copies();
        lifted.forward_store_loads(cfg);
        lifted.propagate_copies();
        // Eliminate dead stores while bases are still Var("ptr_*") — folding
        // can inline constants into bases, losing the ptr_ prefix.
        lifted.eliminate_dead_stores();
        lifted.simplify_all_expressions();
        lifted.fold_expressions(cfg);
        lifted.simplify_all_expressions();
        // Second folding pass: earlier passes may have eliminated intermediate
        // instructions, creating new opportunities for folding across gaps.
        lifted.fold_expressions(cfg);
        lifted.simplify_all_expressions();
        // Cross-block expression folding: inline SDSU values across block boundaries.
        lifted.fold_expressions_cross_block(cfg);
        lifted.simplify_all_expressions();
        // Name stack memory slots as local variables, replacing Load/Store patterns.
        lifted.recover_stack_variables();
        // Stack recovery turns loads into Var references, creating new copy chains
        // (e.g., var_13 = ptr_0_80) that can be propagated away.
        // NOTE: Do NOT run eliminate_dead_stores here — stack stores are now
        // assignments to named variables, not dead stores.
        lifted.propagate_copies();
        lifted.fold_expressions(cfg);
        lifted.simplify_all_expressions();
        lifted.propagate_copies();
        lifted.simplify_all_expressions();

        lifted
    }

    /// Assign variable names to each register definition based on type inference.
    fn assign_variables(&mut self, cfg: &ControlFlowGraph, dataflow: &DataFlowAnalysis) {
        let mut var_counter: usize = 0;
        let mut ptr_counter: usize = 0;
        let mut cond_counter: usize = 0;

        // Build a PC → Instruction index for O(1) lookups during type inference.
        let instruction_at_pc: HashMap<usize, &Instruction> = cfg
            .blocks
            .values()
            .flat_map(|block| block.instructions.iter().map(|(pc, instr)| (*pc, instr)))
            .collect();

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
            let var_type = self.infer_type(def_pc, reg, &instruction_at_pc, dataflow);
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
        instruction_at_pc: &HashMap<usize, &Instruction>,
        dataflow: &DataFlowAnalysis,
    ) -> VarType {
        // Check the defining instruction itself.
        if let Some(instr) = instruction_at_pc.get(&def_pc) {
            let shape = InstructionShape::classify(instr);
            match shape {
                InstructionShape::BinReg {
                    op: BinOp::LtU | BinOp::LtS,
                    ..
                }
                | InstructionShape::BinImm {
                    op: BinOp::LtU | BinOp::LtS,
                    ..
                } => return VarType::Boolean,
                InstructionShape::Unary {
                    op: UnaryOp::Sbrk, ..
                } => return VarType::Pointer,
                _ => {}
            }
        }

        // Check uses: if used as base in a load/store, it's a pointer.
        for chains in dataflow.chains.values() {
            for chain in chains {
                if chain.definition.pc == def_pc && chain.definition.reg == reg {
                    for u in &chain.uses {
                        if let Some(use_instr) = instruction_at_pc.get(&u.pc)
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
        match InstructionShape::classify(instr) {
            InstructionShape::Load { base, .. } | InstructionShape::Store { base, .. } => {
                base == reg
            }
            _ => false,
        }
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
        let shape = InstructionShape::classify(instr);
        match shape {
            InstructionShape::LoadImm { value, .. } => Expression::Const(value),
            InstructionShape::BinReg { op, src1, src2, .. } => self.make_binop(pc, op, src1, src2),
            InstructionShape::BinImm { op, src, value, .. } => {
                self.make_binop_imm(pc, op, src, value as i64)
            }
            InstructionShape::Unary { op, src, .. } => self.make_unary(pc, op, src),
            InstructionShape::Load {
                width,
                base,
                offset,
                ..
            } => self.make_load(pc, width, base, offset),
            InstructionShape::Store {
                width,
                base,
                src,
                offset,
            } => self.make_store(pc, width, base, offset, src),
            InstructionShape::Ecalli { index } => Expression::Call {
                name: "ecalli".to_string(),
                args: vec![Expression::Const(index as i64)],
            },
            InstructionShape::NoOp { name } => Expression::Raw(name.to_string()),
            InstructionShape::Jump { offset } => Expression::Raw(format!("jump {}", offset)),
            InstructionShape::JumpInd { reg, .. } => {
                if self.is_halt_target(pc, reg) {
                    Expression::Raw("halt()".to_string())
                } else {
                    Expression::Raw(format!("jump_ind {}", self.reg_name(pc, reg)))
                }
            }
            InstructionShape::BranchImm {
                cond,
                reg,
                value,
                offset,
            } => Expression::Raw(format!(
                "if ({} {} {}) jump {}",
                self.reg_name(pc, reg),
                cond,
                value,
                offset
            )),
            InstructionShape::BranchReg {
                cond,
                reg1,
                reg2,
                offset,
            } => Expression::Raw(format!(
                "if ({} {} {}) jump {}",
                self.reg_name(pc, reg1),
                cond,
                self.reg_name(pc, reg2),
                offset
            )),
            InstructionShape::Unknown { opcode } => {
                Expression::Raw(format!("/* unknown opcode {:#04x} */", opcode))
            }
        }
    }

    /// Get the variable name for a register used at a given PC, falling back to rN.
    fn reg_name(&self, use_pc: usize, reg: u8) -> String {
        self.var_at_use
            .get(&(use_pc, reg))
            .cloned()
            .unwrap_or_else(|| format!("r{}", reg))
    }

    /// Check if a JumpInd target register holds a known halt address constant.
    /// The PVM halt address is typically -65536 (0xFFFF_FFFF_FFFF_0000).
    fn is_halt_target(&self, use_pc: usize, reg: u8) -> bool {
        // Look up the variable name for this register at this PC.
        if let Some(var_name) = self.var_at_use.get(&(use_pc, reg)) {
            // Find the definition of this variable and check if it's a halt constant.
            for (&(def_pc, _), var) in &self.variables {
                if var.name == *var_name
                    && let Some(Expression::Const(val)) = self.expressions.get(&def_pc)
                {
                    return *val == -65536;
                }
            }
        }
        false
    }

    fn make_binop(&self, pc: usize, op: BinOp, src1: u8, src2: u8) -> Expression {
        Expression::BinOp {
            op,
            lhs: Box::new(Expression::Var(self.reg_name(pc, src1))),
            rhs: Box::new(Expression::Var(self.reg_name(pc, src2))),
        }
    }

    fn make_binop_imm(&self, pc: usize, op: BinOp, src: u8, value: i64) -> Expression {
        Expression::BinOp {
            op,
            lhs: Box::new(Expression::Var(self.reg_name(pc, src))),
            rhs: Box::new(Expression::Const(value)),
        }
    }

    fn make_unary(&self, pc: usize, op: UnaryOp, src: u8) -> Expression {
        Expression::UnaryOp {
            op,
            operand: Box::new(Expression::Var(self.reg_name(pc, src))),
        }
    }

    fn make_load(&self, pc: usize, width: MemWidth, base: u8, offset: i32) -> Expression {
        Expression::Load {
            width,
            base: Box::new(Expression::Var(self.reg_name(pc, base))),
            offset,
        }
    }

    fn make_store(&self, pc: usize, width: MemWidth, base: u8, offset: i32, src: u8) -> Expression {
        Expression::Store {
            width,
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

    /// Fold expressions: when a definition has exactly one use in a later
    /// instruction within the same block (skipping eliminated PCs), inline the expression.
    fn fold_expressions(&mut self, cfg: &ControlFlowGraph) {
        // Build a map of (pc -> [subsequent PCs in same block]) for each block.
        let mut same_block_pcs: HashMap<usize, Vec<usize>> = HashMap::new();
        for block in cfg.blocks.values() {
            for i in 0..block.instructions.len() {
                let cur_pc = block.instructions[i].0;
                let later: Vec<usize> = block.instructions[i + 1..]
                    .iter()
                    .map(|(pc, _)| *pc)
                    .collect();
                same_block_pcs.insert(cur_pc, later);
            }
        }

        // Iterate until no more folding possible.
        let mut changed = true;
        while changed {
            changed = false;

            // Collect candidates: (def_pc, var_name, use_pc) where the def has
            // exactly one use at a later non-eliminated PC in the same block.
            let mut candidates: Vec<(usize, String, usize)> = Vec::new();

            for (&(def_pc, _reg), var) in &self.variables {
                // Skip already eliminated.
                if self.eliminated_pcs.contains(&def_pc) {
                    continue;
                }

                // Must have later instructions in the same block.
                let later_pcs = match same_block_pcs.get(&def_pc) {
                    Some(pcs) => pcs,
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

                // Count actual uses by scanning expression trees (not var_at_use,
                // which becomes stale after folding inlines expressions).
                let use_count = self.count_var_use_sites(&var.name, def_pc);
                if use_count != 1 {
                    continue;
                }

                // Find the use: first later non-eliminated PC in the same block
                // whose expression references this variable.
                let use_pc = later_pcs.iter().copied().find(|&pc| {
                    !self.eliminated_pcs.contains(&pc)
                        && self
                            .expressions
                            .get(&pc)
                            .is_some_and(|e| count_var_refs(e, &var.name) > 0)
                });
                let use_pc = match use_pc {
                    Some(pc) => pc,
                    None => continue,
                };

                // Check depth limit.
                if expression_depth(def_expr) >= 3 {
                    continue;
                }

                candidates.push((def_pc, var.name.clone(), use_pc));
            }

            // Sort by def_pc so that earlier (leaf) definitions are folded
            // before later (compound) definitions that reference them.
            candidates.sort_by_key(|(def_pc, _, _)| *def_pc);

            for (def_pc, var_name, use_pc) in candidates {
                let def_expr = match self.expressions.get(&def_pc) {
                    Some(e) => e.clone(),
                    None => continue,
                };

                if let Some(use_expr) = self.expressions.remove(&use_pc) {
                    let folded = substitute_var(&use_expr, &var_name, &def_expr);
                    self.expressions.insert(use_pc, folded);
                    self.eliminated_pcs.insert(def_pc);
                    changed = true;
                }
            }
        }
    }

    /// Cross-block expression folding: inline SDSU (single-def, single-use) values
    /// across basic block boundaries when safe.
    ///
    /// Safety conditions:
    /// 1. The definition's block must dominate the use's block.
    /// 2. The definition must not be in a loop body if the use is in the loop header
    ///    (prevents circular expressions from loop-carried dependencies).
    /// 3. The expression must not have side effects (no Load/Store — these can't be
    ///    safely moved across blocks).
    fn fold_expressions_cross_block(&mut self, cfg: &ControlFlowGraph) {
        if cfg.blocks.len() <= 1 {
            return;
        }

        let dom_tree = DominatorTree::compute(cfg);

        // Build a map of PC -> block_start_pc for each instruction.
        let mut pc_to_block: HashMap<usize, usize> = HashMap::new();
        for block in cfg.blocks.values() {
            for (pc, _) in &block.instructions {
                pc_to_block.insert(*pc, block.start_pc);
            }
        }

        // Detect loop headers: blocks that are targets of back-edges.
        let loop_headers = detect_loop_headers(cfg, &dom_tree);

        // Collect loop body blocks for each loop header.
        let loop_bodies = collect_loop_bodies(cfg, &dom_tree, &loop_headers);

        let mut changed = true;
        while changed {
            changed = false;

            let mut candidates: Vec<(usize, String, usize)> = Vec::new();

            for (&(def_pc, _reg), var) in &self.variables {
                if self.eliminated_pcs.contains(&def_pc) {
                    continue;
                }

                let def_expr = match self.expressions.get(&def_pc) {
                    Some(e) => e,
                    None => continue,
                };

                // Skip side-effect expressions (Load, Store, Call, Raw).
                if has_side_effects(def_expr) {
                    continue;
                }

                // Depth limit for cross-block folding (more conservative).
                if expression_depth(def_expr) >= 2 {
                    continue;
                }

                // Must have exactly one use site.
                let use_count = self.count_var_use_sites(&var.name, def_pc);
                if use_count != 1 {
                    continue;
                }

                // Find the use site PC.
                let use_pc = self.find_single_use_pc(&var.name, def_pc);
                let use_pc = match use_pc {
                    Some(pc) => pc,
                    None => continue,
                };

                // Must be in different blocks.
                let def_block = match pc_to_block.get(&def_pc) {
                    Some(&b) => b,
                    None => continue,
                };
                let use_block = match pc_to_block.get(&use_pc) {
                    Some(&b) => b,
                    None => continue,
                };
                if def_block == use_block {
                    continue; // Intra-block folding is handled by fold_expressions.
                }

                // Dominance check: def's block must dominate use's block.
                if !dom_tree.dominates(def_block, use_block) {
                    continue;
                }

                // Loop-carried dependency check: don't inline from a loop body
                // into the loop header (would create circular expressions).
                let is_loop_carried = loop_bodies
                    .iter()
                    .any(|(header, body)| body.contains(&def_block) && *header == use_block);
                if is_loop_carried {
                    continue;
                }

                candidates.push((def_pc, var.name.clone(), use_pc));
            }

            candidates.sort_by_key(|(def_pc, _, _)| *def_pc);

            for (def_pc, var_name, use_pc) in candidates {
                let def_expr = match self.expressions.get(&def_pc) {
                    Some(e) => e.clone(),
                    None => continue,
                };

                if let Some(use_expr) = self.expressions.remove(&use_pc) {
                    let folded = substitute_var(&use_expr, &var_name, &def_expr);
                    self.expressions.insert(use_pc, folded);
                    self.eliminated_pcs.insert(def_pc);
                    changed = true;
                }
            }
        }
    }

    /// Find the single non-eliminated PC that references a variable.
    fn find_single_use_pc(&self, var_name: &str, exclude_pc: usize) -> Option<usize> {
        for (&pc, expr) in &self.expressions {
            if pc == exclude_pc || self.eliminated_pcs.contains(&pc) {
                continue;
            }
            let has_ref = match expr {
                Expression::Raw(_) => self
                    .var_at_use
                    .iter()
                    .any(|(&(upc, _), name)| upc == pc && name.as_str() == var_name),
                _ => count_var_refs(expr, var_name) > 0,
            };
            if has_ref {
                return Some(pc);
            }
        }
        None
    }

    /// Count distinct instruction sites that reference a variable, across all remaining
    /// (non-eliminated) expressions and branch conditions.
    /// Uses expression tree scanning (not var_at_use) for structured expressions,
    /// and var_at_use for Raw expressions (branches) where names are embedded as strings.
    fn count_var_use_sites(&self, var_name: &str, exclude_pc: usize) -> usize {
        let mut count = 0;
        for (&pc, expr) in &self.expressions {
            if pc == exclude_pc || self.eliminated_pcs.contains(&pc) {
                continue;
            }
            let has_ref = match expr {
                Expression::Raw(_) => self
                    .var_at_use
                    .iter()
                    .any(|(&(upc, _), name)| upc == pc && name.as_str() == var_name),
                _ => count_var_refs(expr, var_name) > 0,
            };
            if has_ref {
                count += 1;
            }
        }
        count
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

    /// Copy propagation: when a variable is defined as just another variable
    /// (`dst = src`), replace all uses of `dst` with `src` and eliminate the copy.
    fn propagate_copies(&mut self) {
        // Track which copy definitions we've already processed to avoid infinite loops.
        let mut processed: HashSet<usize> = HashSet::new();
        let mut changed = true;
        while changed {
            changed = false;

            // Find definitions that are just Var(other_name).
            // Include eliminated PCs: their variable names may still be referenced
            // in live expressions (e.g., folded into branch conditions).
            let mut copy_defs: Vec<(usize, String, String)> = Vec::new();
            for (&(def_pc, _reg), var) in &self.variables {
                if processed.contains(&def_pc) {
                    continue;
                }
                if let Some(Expression::Var(source_name)) = self.expressions.get(&def_pc)
                    && var.name != *source_name
                {
                    copy_defs.push((def_pc, var.name.clone(), source_name.clone()));
                }
            }

            for (def_pc, dst_name, src_name) in copy_defs {
                processed.insert(def_pc);

                // Replace dst_name with src_name in all var_at_use entries.
                for value in self.var_at_use.values_mut() {
                    if *value == dst_name {
                        *value = src_name.clone();
                    }
                }

                // Replace Var(dst_name) with Var(src_name) in all expressions.
                let replacement = Expression::Var(src_name);
                let pcs: Vec<usize> = self.expressions.keys().copied().collect();
                for pc in pcs {
                    if let Some(expr) = self.expressions.remove(&pc) {
                        let new_expr = substitute_var(&expr, &dst_name, &replacement);
                        self.expressions.insert(pc, new_expr);
                    }
                }

                self.eliminated_pcs.insert(def_pc);
                changed = true;
            }
        }
    }

    /// Store-load forwarding: within each basic block, when a store is followed
    /// by a load from the same address, replace the load with the stored value.
    fn forward_store_loads(&mut self, cfg: &ControlFlowGraph) {
        let mut sorted_blocks: Vec<usize> = cfg.blocks.keys().copied().collect();
        sorted_blocks.sort();

        for &block_pc in &sorted_blocks {
            let block = match cfg.blocks.get(&block_pc) {
                Some(b) => b,
                None => continue,
            };

            // Track stores: (base_str, offset) -> (value_expr, store_pc)
            let mut store_map: HashMap<(String, i32), (Expression, usize)> = HashMap::new();

            for (pc, _instr) in &block.instructions {
                if self.eliminated_pcs.contains(pc) {
                    continue;
                }

                let expr = match self.expressions.get(pc) {
                    Some(e) => e.clone(),
                    None => continue,
                };

                match &expr {
                    Expression::Store {
                        base,
                        offset,
                        value,
                        ..
                    } => {
                        let base_str = format_expression(base);
                        store_map.insert((base_str, *offset), (*value.clone(), *pc));
                    }
                    Expression::Load { base, offset, .. } => {
                        let base_str = format_expression(base);
                        if let Some((stored_value, _store_pc)) = store_map.get(&(base_str, *offset))
                        {
                            // Replace the load expression with the stored value.
                            self.expressions.insert(*pc, stored_value.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Dead store elimination: remove stores to stack locations that are never
    /// read by any remaining load in the program.
    fn eliminate_dead_stores(&mut self) {
        // Collect all (base_str, offset) pairs that appear in remaining Load expressions.
        let mut live_loads: HashSet<(String, i32)> = HashSet::new();
        for (pc, expr) in &self.expressions {
            if self.eliminated_pcs.contains(pc) {
                continue;
            }
            collect_live_loads(expr, &mut live_loads);
        }

        // Eliminate stores whose target is not in any live load and whose base
        // looks like a stack pointer (ptr_* variable).
        let pcs: Vec<usize> = self.expressions.keys().copied().collect();
        for pc in pcs {
            if self.eliminated_pcs.contains(&pc) {
                continue;
            }
            if let Some(Expression::Store { base, offset, .. }) = self.expressions.get(&pc) {
                let base_str = format_expression(base);
                // Only eliminate stores to known stack slots (ptr_* base).
                if base_str.starts_with("ptr_") && !live_loads.contains(&(base_str, *offset)) {
                    self.eliminated_pcs.insert(pc);
                }
            }
        }
    }

    /// Recover stack variables: name stack memory slots (ptr_N + offset) as local
    /// variables, replacing Load expressions with Var references. Stores are kept
    /// but formatted as assignments by `format_pc`.
    fn recover_stack_variables(&mut self) {
        // 1. Scan ALL expressions (including eliminated) for Load/Store with ptr_* base.
        // Eliminated expressions may still be referenced by other expressions
        // (e.g., folded into branch conditions).
        let mut slots: HashSet<(String, i32)> = HashSet::new();
        for expr in self.expressions.values() {
            collect_stack_slots(expr, &mut slots);
        }

        // 2. Create names for each unique (base, offset) pair, sorted by offset.
        let mut sorted_slots: Vec<(String, i32)> = slots.into_iter().collect();
        sorted_slots.sort_by_key(|(base, offset)| (base.clone(), *offset));

        for (base, offset) in &sorted_slots {
            let name = format!("{}_{}", base, offset);
            self.stack_vars
                .insert((base.clone(), *offset), name.clone());
        }

        if self.stack_vars.is_empty() {
            return;
        }

        // 3. Replace Load nodes with Var references in ALL expressions
        // (including eliminated ones that may be embedded in live expressions).
        let pcs: Vec<usize> = self.expressions.keys().copied().collect();
        for pc in pcs {
            if let Some(expr) = self.expressions.remove(&pc) {
                let new_expr = replace_stack_loads(&expr, &self.stack_vars);
                self.expressions.insert(pc, new_expr);
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
    /// Emits `let var = expr` on first definition, plain `var = expr` on reassignment.
    pub fn format_pc(&mut self, pc: usize, instr: &Instruction) -> Option<String> {
        if self.eliminated_pcs.contains(&pc) {
            return None;
        }

        let expr = self.expressions.get(&pc)?;

        // Determine if this instruction defines a register.
        let dst_info = self.def_var_name_with_type(pc, instr);

        match expr {
            Expression::Raw(s) => Some(s.clone()),
            Expression::Store {
                width,
                base,
                offset,
                value,
            } => {
                // Check if this store targets a named stack variable.
                if let Expression::Var(base_name) = base.as_ref()
                    && let Some(slot_name) = self.stack_vars.get(&(base_name.clone(), *offset))
                {
                    let slot_name = slot_name.clone();
                    let value = value.clone();
                    let let_prefix = if self.declared_vars.insert(slot_name.clone()) {
                        "let "
                    } else {
                        ""
                    };
                    return Some(format!(
                        "{}{} = {}",
                        let_prefix,
                        slot_name,
                        format_expression(&value)
                    ));
                }
                let width = *width;
                let base = base.clone();
                let offset = *offset;
                let value = value.clone();
                Some(format!(
                    "{}[{}] = {}",
                    width,
                    format_mem_address(&base, offset),
                    format_expression(&value)
                ))
            }
            Expression::Call { name, args } => {
                let name = name.clone();
                let args = args.clone();
                let arg_strs: Vec<String> = args.iter().map(format_expression).collect();
                if let Some((dst, _)) = dst_info {
                    let let_prefix = if self.declared_vars.insert(dst.clone()) {
                        "let "
                    } else {
                        ""
                    };
                    Some(format!(
                        "{}{} = {}({})",
                        let_prefix,
                        dst,
                        name,
                        arg_strs.join(", ")
                    ))
                } else {
                    Some(format!("{}({})", name, arg_strs.join(", ")))
                }
            }
            _ => {
                let expr = expr.clone();
                if let Some((dst, _)) = dst_info {
                    let let_prefix = if self.declared_vars.insert(dst.clone()) {
                        "let "
                    } else {
                        ""
                    };
                    Some(format!(
                        "{}{} = {}",
                        let_prefix,
                        dst,
                        format_expression(&expr)
                    ))
                } else {
                    Some(format_expression(&expr))
                }
            }
        }
    }

    /// Get the variable name and type for the destination register defined at a PC.
    fn def_var_name_with_type(&self, pc: usize, instr: &Instruction) -> Option<(String, VarType)> {
        let reg = Self::def_reg(instr)?;
        self.variables
            .get(&(pc, reg))
            .map(|v| (v.name.clone(), v.var_type.clone()))
    }

    /// Get the destination register defined by an instruction, if any.
    fn def_reg(instr: &Instruction) -> Option<u8> {
        InstructionShape::classify(instr).def_reg()
    }

    /// Look up the definition expression for a variable by name.
    /// Returns the expression if found and not eliminated.
    pub fn expression_for_var(&self, var_name: &str) -> Option<&Expression> {
        // Find the (def_pc, reg) that produced this variable name
        let (def_pc, _) = self
            .variables
            .iter()
            .find(|(_, v)| v.name == var_name)?
            .0;
        self.expressions.get(def_pc)
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

            match (op, &lhs, &rhs) {
                // Constant folding: C1 + C2, C1 - C2, etc.
                (BinOp::Add, Expression::Const(a), Expression::Const(b)) => {
                    Expression::Const(a.wrapping_add(*b))
                }
                (BinOp::Sub, Expression::Const(a), Expression::Const(b)) => {
                    Expression::Const(a.wrapping_sub(*b))
                }
                (BinOp::Mul, Expression::Const(a), Expression::Const(b)) => {
                    Expression::Const(a.wrapping_mul(*b))
                }
                // x + 0, x - 0, x | 0, x ^ 0, x << 0, x >>u 0, x >>s 0 → x
                (
                    BinOp::Add
                    | BinOp::Sub
                    | BinOp::Or
                    | BinOp::Xor
                    | BinOp::Shl
                    | BinOp::ShrU
                    | BinOp::ShrS,
                    _,
                    Expression::Const(0),
                ) => lhs,
                // 0 + x, 0 | x, 0 ^ x → x (commutative identities)
                (BinOp::Add | BinOp::Or | BinOp::Xor, Expression::Const(0), _) => rhs,
                // (x + C1) + C2 → x + (C1 + C2) — reassociate to fold constants
                (
                    BinOp::Add,
                    Expression::BinOp {
                        op: BinOp::Add,
                        lhs: x,
                        rhs: inner_rhs,
                    },
                    Expression::Const(c2),
                ) if matches!(inner_rhs.as_ref(), Expression::Const(_)) => {
                    let c1 = match inner_rhs.as_ref() {
                        Expression::Const(v) => *v,
                        _ => unreachable!(),
                    };
                    let sum = c1.wrapping_add(*c2);
                    if sum == 0 {
                        *x.clone()
                    } else {
                        Expression::BinOp {
                            op: BinOp::Add,
                            lhs: x.clone(),
                            rhs: Box::new(Expression::Const(sum)),
                        }
                    }
                }
                // x * 1, x /u 1, x /s 1 → x
                (BinOp::Mul | BinOp::DivU | BinOp::DivS, _, Expression::Const(1)) => lhs,
                // 1 * x → x
                (BinOp::Mul, Expression::Const(1), _) => rhs,
                // x * 0 → 0, x & 0 → 0
                (BinOp::Mul | BinOp::And, _, Expression::Const(0)) => Expression::Const(0),
                // 0 * x → 0, 0 & x → 0
                (BinOp::Mul | BinOp::And, Expression::Const(0), _) => Expression::Const(0),
                // bool <u 1 → !bool (negation pattern from SetLtUImm { value: 1 })
                (BinOp::LtU, _, Expression::Const(1)) => Expression::UnaryOp {
                    op: UnaryOp::Not,
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
        } => {
            let base = simplify_expression(*base);
            // Absorb base constant into offset: Load[x + C, off] → Load[x, off + C]
            if let Expression::BinOp {
                op: BinOp::Add,
                ref lhs,
                ref rhs,
            } = base
                && let Expression::Const(c) = rhs.as_ref()
                && let Ok(c32) = i32::try_from(*c)
            {
                return Expression::Load {
                    width,
                    base: lhs.clone(),
                    offset: offset.wrapping_add(c32),
                };
            }
            Expression::Load {
                width,
                base: Box::new(base),
                offset,
            }
        }
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => {
            let base = simplify_expression(*base);
            let value = simplify_expression(*value);
            // Absorb base constant into offset: Store[x + C, off] → Store[x, off + C]
            if let Expression::BinOp {
                op: BinOp::Add,
                ref lhs,
                ref rhs,
            } = base
                && let Expression::Const(c) = rhs.as_ref()
                && let Ok(c32) = i32::try_from(*c)
            {
                return Expression::Store {
                    width,
                    base: lhs.clone(),
                    offset: offset.wrapping_add(c32),
                    value: Box::new(value),
                };
            }
            Expression::Store {
                width,
                base: Box::new(base),
                offset,
                value: Box::new(value),
            }
        }
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
            op: *op,
            lhs: Box::new(substitute_var(lhs, name, replacement)),
            rhs: Box::new(substitute_var(rhs, name, replacement)),
        },
        Expression::UnaryOp { op, operand } => Expression::UnaryOp {
            op: *op,
            operand: Box::new(substitute_var(operand, name, replacement)),
        },
        Expression::Load {
            width,
            base,
            offset,
        } => Expression::Load {
            width: *width,
            base: Box::new(substitute_var(base, name, replacement)),
            offset: *offset,
        },
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => Expression::Store {
            width: *width,
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

/// Collect all distinct variable names referenced in an expression tree.
/// Count occurrences of `Var(name)` in an expression tree.
fn count_var_refs(expr: &Expression, name: &str) -> usize {
    match expr {
        Expression::Var(n) if n == name => 1,
        Expression::Var(_) | Expression::Const(_) | Expression::Raw(_) => 0,
        Expression::BinOp { lhs, rhs, .. } => count_var_refs(lhs, name) + count_var_refs(rhs, name),
        Expression::UnaryOp { operand, .. } => count_var_refs(operand, name),
        Expression::Load { base, .. } => count_var_refs(base, name),
        Expression::Store { base, value, .. } => {
            count_var_refs(base, name) + count_var_refs(value, name)
        }
        Expression::Call { args, .. } => args.iter().map(|a| count_var_refs(a, name)).sum(),
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

/// Recursively collect all (base_str, offset) pairs from Load expressions in an expression tree.
fn collect_live_loads(expr: &Expression, live: &mut HashSet<(String, i32)>) {
    match expr {
        Expression::Load { base, offset, .. } => {
            live.insert((format_expression(base), *offset));
            collect_live_loads(base, live);
        }
        Expression::BinOp { lhs, rhs, .. } => {
            collect_live_loads(lhs, live);
            collect_live_loads(rhs, live);
        }
        Expression::UnaryOp { operand, .. } => {
            collect_live_loads(operand, live);
        }
        Expression::Store { base, value, .. } => {
            collect_live_loads(base, live);
            collect_live_loads(value, live);
        }
        Expression::Call { args, .. } => {
            for arg in args {
                collect_live_loads(arg, live);
            }
        }
        Expression::Const(_) | Expression::Var(_) | Expression::Raw(_) => {}
    }
}

/// Collect all stack slot references (base_ptr_name, offset) from Load and Store
/// expressions where the base is a pointer variable (`ptr_*`).
fn collect_stack_slots(expr: &Expression, slots: &mut HashSet<(String, i32)>) {
    match expr {
        Expression::Load { base, offset, .. } => {
            if let Expression::Var(name) = base.as_ref()
                && name.starts_with("ptr_")
            {
                slots.insert((name.clone(), *offset));
            }
            collect_stack_slots(base, slots);
        }
        Expression::Store {
            base,
            offset,
            value,
            ..
        } => {
            if let Expression::Var(name) = base.as_ref()
                && name.starts_with("ptr_")
            {
                slots.insert((name.clone(), *offset));
            }
            collect_stack_slots(base, slots);
            collect_stack_slots(value, slots);
        }
        Expression::BinOp { lhs, rhs, .. } => {
            collect_stack_slots(lhs, slots);
            collect_stack_slots(rhs, slots);
        }
        Expression::UnaryOp { operand, .. } => collect_stack_slots(operand, slots),
        Expression::Call { args, .. } => {
            for arg in args {
                collect_stack_slots(arg, slots);
            }
        }
        Expression::Const(_) | Expression::Var(_) | Expression::Raw(_) => {}
    }
}

/// Replace Load expressions that access named stack slots with Var references.
/// Store expressions are NOT replaced here (handled by `format_pc` instead).
fn replace_stack_loads(
    expr: &Expression,
    stack_vars: &HashMap<(String, i32), String>,
) -> Expression {
    match expr {
        Expression::Load {
            width,
            base,
            offset,
        } => {
            if let Expression::Var(name) = base.as_ref()
                && let Some(slot_name) = stack_vars.get(&(name.clone(), *offset))
            {
                return Expression::Var(slot_name.clone());
            }
            Expression::Load {
                width: *width,
                base: Box::new(replace_stack_loads(base, stack_vars)),
                offset: *offset,
            }
        }
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => Expression::Store {
            width: *width,
            base: Box::new(replace_stack_loads(base, stack_vars)),
            offset: *offset,
            value: Box::new(replace_stack_loads(value, stack_vars)),
        },
        Expression::BinOp { op, lhs, rhs } => Expression::BinOp {
            op: *op,
            lhs: Box::new(replace_stack_loads(lhs, stack_vars)),
            rhs: Box::new(replace_stack_loads(rhs, stack_vars)),
        },
        Expression::UnaryOp { op, operand } => Expression::UnaryOp {
            op: *op,
            operand: Box::new(replace_stack_loads(operand, stack_vars)),
        },
        Expression::Call { name, args } => Expression::Call {
            name: name.clone(),
            args: args
                .iter()
                .map(|a| replace_stack_loads(a, stack_vars))
                .collect(),
        },
        Expression::Const(_) | Expression::Var(_) | Expression::Raw(_) => expr.clone(),
    }
}

/// Check if an expression has side effects (Load, Store, Call) that prevent
/// safe movement across basic block boundaries.
fn has_side_effects(expr: &Expression) -> bool {
    match expr {
        Expression::Load { .. } | Expression::Store { .. } | Expression::Call { .. } => true,
        Expression::Raw(_) => true,
        Expression::Const(_) | Expression::Var(_) => false,
        Expression::BinOp { lhs, rhs, .. } => has_side_effects(lhs) || has_side_effects(rhs),
        Expression::UnaryOp { operand, .. } => has_side_effects(operand),
    }
}

/// Detect loop headers: blocks that are targets of back-edges (successor dominates predecessor).
fn detect_loop_headers(cfg: &ControlFlowGraph, dom_tree: &DominatorTree) -> HashSet<usize> {
    let mut headers = HashSet::new();
    for block in cfg.blocks.values() {
        for &succ in &block.successors {
            if dom_tree.dominates(succ, block.start_pc) {
                headers.insert(succ);
            }
        }
    }
    headers
}

/// Collect loop body blocks for each loop header by reverse-walking predecessors.
fn collect_loop_bodies(
    cfg: &ControlFlowGraph,
    dom_tree: &DominatorTree,
    headers: &HashSet<usize>,
) -> Vec<(usize, HashSet<usize>)> {
    let mut result = Vec::new();

    for &header in headers {
        let mut body = HashSet::new();
        body.insert(header);

        // Find latch blocks (predecessors of header that header dominates).
        let latches: Vec<usize> = cfg
            .blocks
            .get(&header)
            .map(|b| {
                b.predecessors
                    .iter()
                    .copied()
                    .filter(|&p| dom_tree.dominates(header, p))
                    .collect()
            })
            .unwrap_or_default();

        // Walk backwards from each latch to collect body.
        let mut stack: Vec<usize> = latches;
        while let Some(node) = stack.pop() {
            if body.insert(node)
                && let Some(block) = cfg.blocks.get(&node)
            {
                for &pred in &block.predecessors {
                    if !body.contains(&pred) {
                        stack.push(pred);
                    }
                }
            }
        }

        result.push((header, body));
    }

    result
}

/// Format an Expression tree as a human-readable string with minimal parentheses.
pub fn format_expression(expr: &Expression) -> String {
    match expr {
        Expression::Const(v) => format!("{}", v),
        Expression::Var(name) => name.clone(),
        Expression::Raw(s) => s.clone(),
        Expression::BinOp { op, lhs, rhs } => {
            // Convert `x + -N` to `x - N`.
            if *op == BinOp::Add
                && let Expression::Const(v) = rhs.as_ref()
                && *v < 0
            {
                let lhs_str = format_expression_maybe_parens(lhs, BinOp::Sub, true);
                return format!("{} - {}", lhs_str, -v);
            }
            let lhs_str = format_expression_maybe_parens(lhs, *op, true);
            let rhs_str = format_expression_maybe_parens(rhs, *op, false);
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
            format!("{}[{}]", width, format_mem_address(base, *offset))
        }
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => {
            format!(
                "{}[{}] = {}",
                width,
                format_mem_address(base, *offset),
                format_expression(value)
            )
        }
        Expression::Call { name, args } => {
            let arg_strs: Vec<String> = args.iter().map(format_expression).collect();
            format!("{}({})", name, arg_strs.join(", "))
        }
    }
}

/// Format a memory address `base + offset` with clean output.
fn format_mem_address(base: &Expression, offset: i32) -> String {
    match (base, offset) {
        // Pure constant address: base is 0 → just show offset
        (Expression::Const(0), off) => format!("{}", off),
        // Constant base + offset → fold them
        (Expression::Const(b), off) => format!("{}", (*b).wrapping_add(off as i64)),
        // Zero offset → just base
        (_, 0) => format_expression(base),
        // Negative offset
        (_, off) if off < 0 => format!("{} - {}", format_expression(base), -off),
        // Positive offset
        (_, off) => format!("{} + {}", format_expression(base), off),
    }
}

/// Format a sub-expression, adding parentheses only when needed for precedence.
fn format_expression_maybe_parens(expr: &Expression, parent_op: BinOp, _is_left: bool) -> String {
    match expr {
        Expression::BinOp { op, .. } => {
            let needs_parens = op_precedence(*op) < op_precedence(parent_op);
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
fn op_precedence(op: BinOp) -> u8 {
    match op {
        BinOp::Or => 1,
        BinOp::Xor => 2,
        BinOp::And => 3,
        BinOp::LtU | BinOp::LtS => 4,
        BinOp::Shl | BinOp::ShrU | BinOp::ShrS => 5,
        BinOp::Add | BinOp::Sub => 6,
        BinOp::Mul | BinOp::DivU | BinOp::DivS | BinOp::RemU | BinOp::RemS => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_test_cfg;
    use crate::dataflow::DataFlowAnalysis;

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

        // PC 4's expression should be the folded result: 42 + 1 = 43.
        let expr = lifted.expressions.get(&4).unwrap();
        let formatted = format_expression(expr);
        assert!(
            formatted.contains("43"),
            "Expression should contain folded constant 43 (42 + 1), got: {}",
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
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

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
        // With constant folding, 42+1=43, then 43*43=1849.
        assert!(
            line.contains("1849"),
            "Should contain fully folded constant 1849 (43*43), got: {}",
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
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_xor_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Xor,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_mul_one() {
        let expr = Expression::BinOp {
            op: BinOp::Mul,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "x");
    }

    #[test]
    fn test_simplify_mul_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Mul,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "0");
    }

    #[test]
    fn test_simplify_and_zero() {
        let expr = Expression::BinOp {
            op: BinOp::And,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "0");
    }

    #[test]
    fn test_simplify_ltu_1_negation() {
        let expr = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Var("cond_0".to_string())),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified), "!(cond_0)");
    }

    #[test]
    fn test_simplify_shift_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Shl,
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
            op: BinOp::Mul,
            lhs: Box::new(Expression::BinOp {
                op: BinOp::Add,
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
            op: BinOp::Add,
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
            op: BinOp::Mul,
            lhs: Box::new(Expression::BinOp {
                op: BinOp::Add,
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
            op: BinOp::Add,
            lhs: Box::new(Expression::BinOp {
                op: BinOp::Mul,
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

    #[test]
    fn test_cross_block_expression_folding() {
        // Block 0: r0 = 100 (ptr); r1 = r0 + 8
        // Block 10: r2 = r1 + 16; trap
        // r1 has single use across blocks; block 0 dominates block 10 -> should be folded.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 100 }),
                        (
                            4,
                            Instruction::AddImm32 {
                                dst: 1,
                                src: 0,
                                value: 8,
                            },
                        ),
                    ],
                    vec![10],
                ),
                (
                    10,
                    vec![
                        (
                            10,
                            Instruction::AddImm32 {
                                dst: 2,
                                src: 1,
                                value: 16,
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

        // r1's definition at PC 4 should be folded into PC 10 (cross-block).
        assert!(
            lifted.eliminated_pcs.contains(&4),
            "PC 4 (r1 = r0 + 8) should be eliminated by cross-block folding"
        );

        // The expression at PC 10 should contain the folded result.
        // With constant propagation (r0=100) and simplification, it becomes 100 + 8 + 16 = 124.
        let expr = lifted.expressions.get(&10).unwrap();
        let formatted = format_expression(expr);
        assert!(
            formatted.contains("124"),
            "Expression should be folded to 124 (100 + 8 + 16), got: {}",
            formatted
        );
    }

    #[test]
    fn test_cross_block_no_fold_in_loop() {
        // Block 0: r0 = 1 (init)
        // Block 10 (loop header): r1 = r0 + 1; branch back to 10 or exit to 20
        // Block 20: trap
        // r0 is defined in block 0, used in loop header block 10.
        // Block 0 dominates block 10, but r0 is not defined in a loop body,
        // so this would normally be safe. However, if r0 has other definitions
        // in the loop body, it shouldn't be folded. This tests the basic case.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::LoadImm { reg: 0, value: 1 })],
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
                        (
                            14,
                            Instruction::AddImm32 {
                                dst: 0,
                                src: 1,
                                value: 0,
                            },
                        ),
                        (
                            18,
                            Instruction::BranchNeImm {
                                reg: 0,
                                value: 10,
                                offset: -8,
                            },
                        ),
                    ],
                    vec![10, 22],
                ),
                (22, vec![(22, Instruction::Trap)], vec![]),
            ],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // r0 defined at PC 0 is used in the loop header. Since r0 is redefined
        // at PC 14 inside the loop, the def at PC 0 has multiple uses (PC 10
        // on each iteration via the redefinition). The analysis should handle
        // this correctly without creating circular expressions.
        // Just verify it doesn't panic and produces output.
        assert!(!lifted.expressions.is_empty());
    }

    #[test]
    fn test_cross_block_no_fold_side_effects() {
        // Block 0: r0 = load_u32(r2, 0)   (side effect - memory load)
        // Block 10: r1 = r0 + 1; trap
        // r0 is SDSU across blocks, block 0 dominates block 10, but r0's definition
        // is a Load expression which has side effects -> should NOT be folded.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::LoadIndU32 {
                            dst: 0,
                            base: 2,
                            offset: 0,
                        },
                    )],
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

        // PC 0 (Load) should NOT be eliminated because loads have side effects.
        assert!(
            !lifted.eliminated_pcs.contains(&0),
            "Load at PC 0 should not be folded across blocks (side effect)"
        );
    }

    #[test]
    fn test_copy_propagation() {
        // r0 = 10; r1 = r0 (move/add 0); r2 = r1 + 5; trap
        // After copy propagation, r1 = r0 should be eliminated and r2 should use r0's var name.
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 10 }),
                    (
                        4,
                        Instruction::AddImm32 {
                            dst: 1,
                            src: 0,
                            value: 0,
                        },
                    ),
                    (
                        8,
                        Instruction::AddImm32 {
                            dst: 2,
                            src: 1,
                            value: 5,
                        },
                    ),
                    (12, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // PC 4 (the copy r1 = r0 + 0 = r0) should be eliminated.
        assert!(
            lifted.eliminated_pcs.contains(&4),
            "Copy at PC 4 should be eliminated"
        );
    }

    #[test]
    fn test_store_load_forwarding() {
        // r0 = 100 (ptr); store u64[r0+8] = r1; r2 = load u64[r0+8]; trap
        // The load should be forwarded to use r1's value directly.
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 100 }),
                    (4, Instruction::LoadImm { reg: 1, value: 42 }),
                    (
                        8,
                        Instruction::StoreIndU64 {
                            base: 0,
                            src: 1,
                            offset: 8,
                        },
                    ),
                    (
                        12,
                        Instruction::LoadIndU64 {
                            dst: 2,
                            base: 0,
                            offset: 8,
                        },
                    ),
                    (16, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // PC 12 (the load) should have been forwarded to the stored value,
        // not remain as a Load expression.
        let expr = lifted.expressions.get(&12).unwrap();
        assert!(
            !matches!(expr, Expression::Load { .. }),
            "Load at PC 12 should have been forwarded, got: {}",
            format_expression(expr)
        );
    }

    #[test]
    fn test_dead_store_elimination() {
        // r0 = 100 (ptr); store u64[r0+8] = r1; store u64[r0+16] = r1; trap
        // Both stores are never loaded, so they should be eliminated.
        // Two stores so r0 has multiple uses and isn't constant-propagated.
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 100 }),
                    (4, Instruction::LoadImm { reg: 1, value: 42 }),
                    (
                        8,
                        Instruction::StoreIndU64 {
                            base: 0,
                            src: 1,
                            offset: 8,
                        },
                    ),
                    (
                        12,
                        Instruction::StoreIndU64 {
                            base: 0,
                            src: 1,
                            offset: 16,
                        },
                    ),
                    (16, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // r0 is used as a base in stores, so it should be inferred as a pointer (ptr_*).
        let var = lifted.variables.get(&(0, 0)).unwrap();
        assert!(
            var.name.starts_with("ptr_"),
            "Base register should be a pointer, got: {}",
            var.name
        );

        // The store at PC 8 should be eliminated since no load reads from it.
        assert!(
            lifted.eliminated_pcs.contains(&8),
            "Dead store at PC 8 should be eliminated"
        );
        // The store at PC 12 should also be eliminated.
        assert!(
            lifted.eliminated_pcs.contains(&12),
            "Dead store at PC 12 should be eliminated"
        );
    }

    #[test]
    fn test_store_load_forward_then_dead_store() {
        // r0 = 100 (ptr); r1 = 7; store u64[r0+16] = r1; r2 = load u64[r0+16];
        // r3 = r2 + r4; store u64[r0+32] = r3; trap
        // r2 is used at PC 20 (different reg from r4), and r4 used at PC 20.
        // r0 has multiple uses (base in 3 stores/loads), not constant-propagated.
        // r2 has uses at PC 20 and PC 24 (two distinct use sites via different instructions),
        // preventing fold. After forwarding, load at PC 12 replaced. After DSE, store at PC 8 removed.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 100 }),
                        (4, Instruction::LoadImm { reg: 1, value: 7 }),
                        (
                            8,
                            Instruction::StoreIndU64 {
                                base: 0,
                                src: 1,
                                offset: 16,
                            },
                        ),
                        (
                            12,
                            Instruction::LoadIndU64 {
                                dst: 2,
                                base: 0,
                                offset: 16,
                            },
                        ),
                    ],
                    vec![20],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::AddImm32 {
                                dst: 3,
                                src: 2,
                                value: 1,
                            },
                        ),
                        (
                            24,
                            Instruction::AddImm32 {
                                dst: 4,
                                src: 2,
                                value: 2,
                            },
                        ),
                        (28, Instruction::Trap),
                    ],
                    vec![],
                ),
            ],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // The load at PC 12 should not be a Load expression anymore.
        let expr12 = lifted.expressions.get(&12);
        if let Some(e) = expr12 {
            assert!(
                !matches!(e, Expression::Load { .. }),
                "Load should have been forwarded, got: {}",
                format_expression(e)
            );
        }

        // The store at PC 8 should be eliminated (dead store after forwarding).
        assert!(
            lifted.eliminated_pcs.contains(&8),
            "Store at PC 8 should be a dead store after forwarding"
        );
    }
}
