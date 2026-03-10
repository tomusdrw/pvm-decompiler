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
use crate::ir::ssa::SsaProgram;
use crate::structuring::DominatorTree;
use std::collections::{HashMap, HashSet};
use std::fmt;
use wasm_pvm::pvm::Instruction;

/// Formatting context threaded through expression rendering.
/// Replaces the former thread-local `MEMORY_BASE` global state.
#[derive(Debug, Clone, Default)]
pub struct FormatContext {
    /// The PVM linear memory base address.
    /// When set, expressions involving this constant are simplified
    /// (e.g. `addr + MEMORY_BASE` → `pvm_addr(addr)`).
    pub memory_base: Option<u64>,
    /// Linear memory offset for heap accesses (e.g. 0x50000 for AS programs).
    /// When set, pointer dereferences through this offset render as `*ptr`.
    pub linear_memory_offset: Option<u64>,
    /// Whether formatting currently occurs in memory-dereference context.
    /// Some simplifications are only semantics-safe in this context.
    pub deref_context: bool,
}

impl FormatContext {
    /// Create a context with the given memory base.
    pub fn new(memory_base: Option<u64>) -> Self {
        Self {
            memory_base,
            linear_memory_offset: None,
            deref_context: false,
        }
    }

    fn with_deref_context(&self) -> Self {
        let mut next = self.clone();
        next.deref_context = true;
        next
    }
}

/// Inferred variable type based on usage context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    /// Unsigned 64-bit integer (default).
    U64,
    /// Signed 64-bit integer (used in signed operations).
    I64,
    /// Unsigned 32-bit integer (produced by 32-bit operations).
    U32,
    /// Signed 32-bit integer (produced by signed 32-bit operations).
    I32,
    /// Pointer (used in memory address computations).
    Pointer,
    /// Boolean (produced by comparisons).
    Boolean,
}

impl fmt::Display for VarType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VarType::U64 => write!(f, "u64"),
            VarType::I64 => write!(f, "i64"),
            VarType::U32 => write!(f, "u32"),
            VarType::I32 => write!(f, "i32"),
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
    /// Call targets: maps callee_entry_pc → callee function name (for direct Jump calls).
    pub call_targets: HashMap<usize, String>,
    /// Direct call sites: maps Jump instruction PC → callee function name.
    /// Used for exact callsite labeling when shared jump targets are ambiguous.
    pub direct_call_sites: HashMap<usize, String>,
    /// Function parameter registers by callee function name.
    /// Used to render explicit call arguments at call sites.
    pub call_param_regs: HashMap<String, Vec<u8>>,
    /// Reverse index: variable name → definition PC for O(1) lookups.
    pub var_name_to_def_pc: HashMap<String, usize>,
    /// Epilogue blocks: maps block_pc → epilogue kind (Return or Halt).
    /// Used by emission to render `return` / `halt()` instead of raw instructions.
    pub epilogue_blocks: HashMap<usize, crate::functions::EpilogueKind>,
    /// Blocks to completely suppress from output (e.g., callee blocks misassigned to caller).
    pub suppressed_blocks: HashSet<usize>,
    /// Linear memory base address (e.g. 0x50000 = 327680 for PVM).
    /// When set, expressions involving this constant are simplified.
    pub memory_base: Option<u64>,
    /// Detected heap allocation boilerplate pattern (AssemblyScript).
    pub heap_alloc: Option<crate::functions::HeapAllocPattern>,
    /// Block labels to hide from output (e.g., convergence block after heap alloc suppression).
    pub hidden_labels: HashSet<usize>,
    /// Linear memory offset for heap accesses (e.g. 0x50000 for AS programs).
    pub linear_memory_offset: Option<u64>,
    /// Variable name for the data pointer in heap allocation (e.g. "ptr_0_88").
    /// When set, heap_alloc() is emitted as `data_ptr = heap_alloc(size)`.
    pub heap_alloc_data_ptr: Option<String>,
}

impl LiftedProgram {
    /// Build a `FormatContext` from this program's settings.
    pub fn format_context(&self) -> FormatContext {
        let mut ctx = FormatContext::new(self.memory_base);
        ctx.linear_memory_offset = self.linear_memory_offset;
        ctx
    }
}

/// A set of variable declarations collected for a block, to be emitted at its top.
impl LiftedProgram {
    /// Run the full lifting pipeline on a CFG with dataflow information.
    /// Convenience method that computes its own dominator tree.
    /// Use `analyze_with_dom_tree` when sharing a pre-computed tree.
    #[cfg(test)]
    pub fn analyze(cfg: &ControlFlowGraph, dataflow: &DataFlowAnalysis) -> Self {
        let dom_tree = DominatorTree::compute(cfg);
        Self::analyze_with_dom_tree(cfg, dataflow, &dom_tree)
    }

    /// Run the full lifting pipeline, reusing a pre-computed dominator tree.
    pub fn analyze_with_dom_tree(
        cfg: &ControlFlowGraph,
        dataflow: &DataFlowAnalysis,
        dom_tree: &DominatorTree,
    ) -> Self {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: None,
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        };

        lifted.assign_variables(cfg, dataflow);
        // Build SSA and lower it back into lifted use-site bindings so
        // expression building uses proof-backed reaching definitions.
        let ssa = SsaProgram::build(cfg, dom_tree);
        lifted.lower_ssa_to_lifted_uses(&ssa);
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
        lifted.fold_expressions_cross_block(cfg, dom_tree, &ssa);
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

    /// Lower SSA value mappings back to non-SSA use bindings (`var_at_use`).
    /// This keeps existing lifted/emission stages unchanged while making
    /// use-site naming depend on explicit SSA reaching-definition proofs.
    fn lower_ssa_to_lifted_uses(&mut self, ssa: &SsaProgram) {
        for (&(use_pc, use_reg), &value_id) in ssa.use_mappings() {
            let resolved_name = match ssa.value_kind(value_id) {
                Some(crate::ir::ssa::SsaValueKind::Instr { pc, reg, .. }) => {
                    self.variables.get(&(*pc, *reg)).map(|v| v.name.clone())
                }
                Some(crate::ir::ssa::SsaValueKind::Phi { .. }) => {
                    self.resolve_phi_to_single_name(ssa, value_id)
                }
                _ => None,
            };
            if let Some(name) = resolved_name {
                self.var_at_use.insert((use_pc, use_reg), name);
            }
        }
    }

    /// If all phi operands resolve to the same concrete definition name,
    /// reuse that name; otherwise leave the existing mapping unchanged.
    fn resolve_phi_to_single_name(&self, ssa: &SsaProgram, phi_id: usize) -> Option<String> {
        let mut unique_name: Option<String> = None;
        let operands = ssa.value_operands(phi_id)?;
        if operands.is_empty() {
            return None;
        }
        for &operand in operands {
            let kind = ssa.value_kind(operand)?;
            let name = match kind {
                crate::ir::ssa::SsaValueKind::Instr { pc, reg, .. } => {
                    self.variables.get(&(*pc, *reg)).map(|v| v.name.clone())?
                }
                _ => return None,
            };
            match &unique_name {
                Some(existing) if existing != &name => return None,
                Some(_) => {}
                None => unique_name = Some(name),
            }
        }
        unique_name
    }

    /// Coalesce two variable names: rename all occurrences of `old_name` to `new_name`.
    /// Used to unify loop induction variable names across init/step definitions.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn coalesce_variable(&mut self, old_name: &str, new_name: &str) {
        if old_name == new_name {
            return;
        }

        // Rename in variables map
        for var in self.variables.values_mut() {
            if var.name == old_name {
                var.name = new_name.to_string();
            }
        }

        // Rename in var_at_use map
        for name in self.var_at_use.values_mut() {
            if *name == old_name {
                *name = new_name.to_string();
            }
        }

        // Rename in expressions (Var references)
        for expr in self.expressions.values_mut() {
            rename_var_in_expression(expr, old_name, new_name);
        }

        // Update declared_vars
        if self.declared_vars.remove(old_name) {
            self.declared_vars.insert(new_name.to_string());
        }

        // Update reverse index: remove old entry, only insert if new_name
        // doesn't already have an entry (keep the earliest definition).
        if let Some(def_pc) = self.var_name_to_def_pc.remove(old_name) {
            self.var_name_to_def_pc
                .entry(new_name.to_string())
                .or_insert(def_pc);
        }
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

        // Build a (def_pc, reg) → uses index from chains for O(1) lookup in infer_type.
        let mut chain_uses_index: HashMap<(usize, u8), Vec<&crate::dataflow::Use>> = HashMap::new();
        for chains in dataflow.chains.values() {
            for chain in chains {
                let key = (chain.definition.pc, chain.definition.reg);
                chain_uses_index
                    .entry(key)
                    .or_default()
                    .extend(chain.uses.iter());
            }
        }

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
            let var_type = self.infer_type(def_pc, reg, &instruction_at_pc, &chain_uses_index);
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
            self.var_name_to_def_pc.insert(name, def_pc);
            self.variables.insert((def_pc, reg), variable);
        }

        // Build use-site mapping: for each use of a register at a PC, find which
        // definition's variable name to use.
        // When multiple definitions reach the same use, prefer the one with the
        // smallest definition PC for deterministic output.
        let mut var_at_use_def_pc: HashMap<(usize, u8), usize> = HashMap::new();
        for chains in dataflow.chains.values() {
            for chain in chains {
                let def_pc = chain.definition.pc;
                if let Some(var) = self.variables.get(&(def_pc, chain.definition.reg)) {
                    let name = var.name.clone();
                    for u in &chain.uses {
                        let key = (u.pc, u.reg);
                        let prev_def = var_at_use_def_pc.get(&key).copied();
                        if prev_def.is_none() || def_pc < prev_def.unwrap() {
                            self.var_at_use.insert(key, name.clone());
                            var_at_use_def_pc.insert(key, def_pc);
                        }
                    }
                }
            }
        }
    }

    /// Infer the type of a variable from how it is defined and used.
    fn infer_type(
        &self,
        def_pc: usize,
        reg: u8,
        instruction_at_pc: &HashMap<usize, &Instruction>,
        chain_uses_index: &HashMap<(usize, u8), Vec<&crate::dataflow::Use>>,
    ) -> VarType {
        use crate::instruction::BitWidth;

        // Helper: check if any use of this definition is as a base in a load/store.
        let is_pointer_use = || -> bool {
            if let Some(uses) = chain_uses_index.get(&(def_pc, reg)) {
                for u in uses {
                    if let Some(use_instr) = instruction_at_pc.get(&u.pc)
                        && Self::is_used_as_base(use_instr, reg)
                    {
                        return true;
                    }
                }
            }
            false
        };

        // Check the defining instruction itself.
        if let Some(instr) = instruction_at_pc.get(&def_pc) {
            let shape = InstructionShape::classify(instr);
            match &shape {
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

            // Check for width and signedness from the defining operation.
            let (width, signed) = match &shape {
                InstructionShape::BinReg { op, width, .. }
                | InstructionShape::BinImm { op, width, .. } => {
                    let signed = matches!(op, BinOp::DivS | BinOp::RemS | BinOp::ShrS);
                    (Some(*width), signed)
                }
                InstructionShape::Unary { op, .. } => {
                    let signed = matches!(op, UnaryOp::Sext8 | UnaryOp::Sext16);
                    (None, signed)
                }
                _ => (None, false),
            };

            // Check uses: if used as base in a load/store, it's a pointer.
            if is_pointer_use() {
                return VarType::Pointer;
            }

            // Determine type from width and signedness.
            return match (width, signed) {
                (Some(BitWidth::W32), true) => VarType::I32,
                (Some(BitWidth::W32), false) => VarType::U32,
                (_, true) => VarType::I64,
                _ => VarType::U64,
            };
        }

        // No defining instruction found — check uses for pointer context.
        if is_pointer_use() {
            return VarType::Pointer;
        }

        VarType::U64
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
                name: ecalli_name(index),
                args: vec![],
            },
            InstructionShape::NoOp { name } => {
                let display_name = if name == "trap" { "return" } else { name };
                Expression::Raw(display_name.to_string())
            }
            InstructionShape::Jump { offset } => Expression::Raw(format!("jump {}", offset)),
            InstructionShape::JumpInd { reg, .. } => {
                if self.is_halt_target(pc, reg) {
                    Expression::Raw("halt()".to_string())
                } else {
                    Expression::Raw(format!("call_indirect({})", self.reg_name(pc, reg)))
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
            InstructionShape::BinImmRev { op, src, value, .. } => {
                self.make_binop_imm_rev(pc, op, src, value as i64)
            }
            InstructionShape::CmovReg {
                is_zero,
                dst,
                src,
                cond,
            } => {
                let cond_str = if is_zero { "== 0" } else { "!= 0" };
                Expression::Raw(format!(
                    "if ({} {}) {} = {}",
                    self.reg_name(pc, cond),
                    cond_str,
                    self.var_name_for_def(pc, dst),
                    self.reg_name(pc, src)
                ))
            }
            InstructionShape::CmovImm {
                is_zero,
                dst,
                cond,
                value,
            } => {
                let cond_str = if is_zero { "== 0" } else { "!= 0" };
                Expression::Raw(format!(
                    "if ({} {}) {} = {}",
                    self.reg_name(pc, cond),
                    cond_str,
                    self.var_name_for_def(pc, dst),
                    value
                ))
            }
            InstructionShape::LoadImmJump { dst, value, .. } => {
                Expression::Raw(format!("{} = {}", self.var_name_for_def(pc, dst), value,))
            }
            InstructionShape::LoadImmJumpInd { base, dst, value } => Expression::Raw(format!(
                "{} = {}; jump_ind {}",
                self.var_name_for_def(pc, dst),
                value,
                self.reg_name(pc, base)
            )),
            InstructionShape::LoadAbsolute {
                width,
                dst: _,
                address,
            } => self.make_load_absolute(pc, width, address),
            InstructionShape::StoreAbsolute {
                width,
                src,
                address,
            } => self.make_store_absolute(pc, width, address, src),
            InstructionShape::StoreImm {
                width,
                address,
                value,
            } => Expression::Raw(format!("{}[{:#x}] = {}", width, address, value)),
            InstructionShape::StoreImmInd {
                width,
                base,
                offset,
                value,
            } => Expression::Raw(format!(
                "{}[{} + {}] = {}",
                width,
                self.reg_name(pc, base),
                format_const(offset as i64),
                value
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

    /// Check if a JumpInd target register holds a known function entry address.
    /// Returns the function name if the register is a constant matching a call target.
    pub fn resolve_indirect_call(&self, use_pc: usize, reg: u8) -> Option<String> {
        if self.call_targets.is_empty() {
            return None;
        }
        if let Some(var_name) = self.var_at_use.get(&(use_pc, reg))
            && let Some(Expression::Const(val)) = self.expression_for_var(var_name)
        {
            let addr = *val as usize;
            return self.call_targets.get(&addr).cloned();
        }
        None
    }

    /// Check if a JumpInd target register holds a known halt address constant.
    /// The PVM halt address is typically -0x10000 (0xFFFF_FFFF_FFFF_0000).
    fn is_halt_target(&self, use_pc: usize, reg: u8) -> bool {
        if let Some(var_name) = self.var_at_use.get(&(use_pc, reg))
            && let Some(Expression::Const(val)) = self.expression_for_var(var_name)
        {
            return *val == -0x10000;
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

    fn make_binop_imm_rev(&self, pc: usize, op: BinOp, src: u8, value: i64) -> Expression {
        Expression::BinOp {
            op,
            lhs: Box::new(Expression::Const(value)),
            rhs: Box::new(Expression::Var(self.reg_name(pc, src))),
        }
    }

    fn make_load_absolute(&self, _pc: usize, width: MemWidth, address: i32) -> Expression {
        Expression::Load {
            width,
            base: Box::new(Expression::Const(0)),
            offset: address,
        }
    }

    fn make_store_absolute(&self, pc: usize, width: MemWidth, address: i32, src: u8) -> Expression {
        Expression::Store {
            width,
            base: Box::new(Expression::Const(0)),
            offset: address,
            value: Box::new(Expression::Var(self.reg_name(pc, src))),
        }
    }

    fn var_name_for_def(&self, pc: usize, reg: u8) -> String {
        self.variables
            .get(&(pc, reg))
            .map(|v| v.name.clone())
            .unwrap_or_else(|| format!("r{}", reg))
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

            // Build variable-use index for O(1) use-count lookups.
            let var_use_index =
                build_var_use_index(&self.expressions, &self.var_at_use, &self.eliminated_pcs);

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

                // O(1) use count via precomputed index.
                let use_pcs = var_use_index.get(&var.name);
                let use_count = use_pcs
                    .map(|pcs| pcs.iter().filter(|&&pc| pc != def_pc).count())
                    .unwrap_or(0);
                if use_count != 1 {
                    continue;
                }

                // Find the use: first later non-eliminated PC in the same block
                // whose expression references this variable.
                let use_pc = later_pcs
                    .iter()
                    .copied()
                    .find(|pc| use_pcs.is_some_and(|pcs| pcs.contains(pc)));
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
    fn fold_expressions_cross_block(
        &mut self,
        cfg: &ControlFlowGraph,
        dom_tree: &DominatorTree,
        ssa: &SsaProgram,
    ) {
        if cfg.blocks.len() <= 1 {
            return;
        }

        // Build a map of PC -> block_start_pc for each instruction.
        let mut pc_to_block: HashMap<usize, usize> = HashMap::new();
        for block in cfg.blocks.values() {
            for (pc, _) in &block.instructions {
                pc_to_block.insert(*pc, block.start_pc);
            }
        }

        // Detect loop headers: blocks that are targets of back-edges.
        let loop_headers = detect_loop_headers(cfg, dom_tree);

        // Collect loop body blocks for each loop header.
        let loop_bodies = collect_loop_bodies(cfg, dom_tree, &loop_headers);

        let mut changed = true;
        while changed {
            changed = false;

            let mut candidates: Vec<(usize, String, usize)> = Vec::new();

            for (&(def_pc, reg), var) in &self.variables {
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

                // Proof obligation #1: definition must have exactly one SSA use.
                let Some(ssa_value) = ssa.value_for_def_pc_reg(def_pc, reg) else {
                    continue;
                };
                if ssa.use_count(ssa_value) != 1 {
                    continue;
                }

                // Proof obligation #2: use must be a single instruction use
                // (not a phi-merge operand).
                let use_pc = match ssa.single_instruction_use_pc(ssa_value) {
                    Some(pc) => pc,
                    None => continue,
                };
                if use_pc == def_pc || self.eliminated_pcs.contains(&use_pc) {
                    continue;
                }

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

                // Proof obligation #3: SSA def must dominate the use.
                if !ssa.value_definition_dominates_use_pc(ssa_value, use_pc, dom_tree) {
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
        loop {
            // Find ALL copy definitions in this iteration and resolve chains.
            // E.g., if a = b, b = c, resolve a -> c directly.
            let mut rename_map: HashMap<String, String> = HashMap::new();
            let mut copy_def_pcs: Vec<usize> = Vec::new();

            for (&(def_pc, _reg), var) in &self.variables {
                if processed.contains(&def_pc) {
                    continue;
                }
                if let Some(Expression::Var(source_name)) = self.expressions.get(&def_pc)
                    && var.name != *source_name
                {
                    rename_map.insert(var.name.clone(), source_name.clone());
                    copy_def_pcs.push(def_pc);
                }
            }

            if rename_map.is_empty() {
                break;
            }

            // Resolve transitive chains: if a->b and b->c, resolve a->c.
            let keys: Vec<String> = rename_map.keys().cloned().collect();
            for key in &keys {
                let mut target = rename_map[key].clone();
                let mut seen = HashSet::new();
                seen.insert(key.clone());
                while let Some(next) = rename_map.get(&target) {
                    if seen.contains(next) {
                        break; // cycle
                    }
                    seen.insert(target.clone());
                    target = next.clone();
                }
                rename_map.insert(key.clone(), target);
            }

            // Apply all renames in a single traversal per expression.
            for expr in self.expressions.values_mut() {
                rename_vars_multi(expr, &rename_map);
            }

            // Apply all renames in a single pass over var_at_use.
            for value in self.var_at_use.values_mut() {
                if let Some(src_name) = rename_map.get(value.as_str()) {
                    *value = src_name.clone();
                }
            }

            for def_pc in copy_def_pcs {
                processed.insert(def_pc);
                self.eliminated_pcs.insert(def_pc);
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
                        let base_str = format_expression(base, &self.format_context());
                        store_map.insert((base_str, *offset), (*value.clone(), *pc));
                    }
                    Expression::Load { base, offset, .. } => {
                        let base_str = format_expression(base, &self.format_context());
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
        let ctx = self.format_context();
        // Collect all (base_str, offset) pairs that appear in remaining Load expressions.
        let mut live_loads: HashSet<(String, i32)> = HashSet::new();
        for (pc, expr) in &self.expressions {
            if self.eliminated_pcs.contains(pc) {
                continue;
            }
            collect_live_loads(expr, &ctx, &mut live_loads);
        }

        // Eliminate stores whose target is not in any live load and whose base
        // has proven stack-slot provenance.
        let pcs: Vec<usize> = self.expressions.keys().copied().collect();
        for pc in pcs {
            if self.eliminated_pcs.contains(&pc) {
                continue;
            }
            if let Some(Expression::Store { base, offset, .. }) = self.expressions.get(&pc) {
                let base_str = format_expression(base, &ctx);
                // Keep stores unless the base expression can be traced back to
                // stack-pointer-derived address arithmetic. This avoids dropping
                // writes through pointers loaded from stack slots.
                if self.has_stack_slot_provenance(base)
                    && (*offset >= 0 && *offset < 0x10000)
                    && !live_loads.contains(&(base_str, *offset))
                {
                    self.eliminated_pcs.insert(pc);
                }
            }
        }
    }

    fn has_stack_slot_provenance(&self, base: &Expression) -> bool {
        let mut visiting = HashSet::new();
        self.expression_has_stack_slot_provenance(base, &mut visiting, 0)
    }

    fn expression_has_stack_slot_provenance(
        &self,
        expr: &Expression,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        if depth > 20 {
            return false;
        }
        match expr {
            Expression::Var(name) => {
                self.variable_has_stack_slot_provenance(name, visiting, depth + 1)
            }
            Expression::BinOp { op, lhs, rhs } => {
                (matches!(op, BinOp::Add | BinOp::Sub)
                    && self.expression_has_stack_slot_provenance(lhs, visiting, depth + 1)
                    && self.expression_is_constant_like(rhs, visiting, depth + 1))
                    || (*op == BinOp::Add
                        && self.expression_has_stack_slot_provenance(rhs, visiting, depth + 1)
                        && self.expression_is_constant_like(lhs, visiting, depth + 1))
            }
            _ => false,
        }
    }

    fn variable_has_stack_slot_provenance(
        &self,
        name: &str,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        if !visiting.insert(name.to_string()) {
            return false;
        }

        let result = self
            .var_name_to_def_pc
            .get(name)
            .copied()
            .is_some_and(|def_pc| {
                // SP is register 1 in the PVM ABI.
                let is_sp_def = self
                    .variables
                    .iter()
                    .any(|(&(pc, reg), var)| pc == def_pc && var.name == name && reg == 1);
                if is_sp_def {
                    return true;
                }
                self.expressions.get(&def_pc).is_some_and(|expr| {
                    self.expression_has_stack_slot_provenance(expr, visiting, depth + 1)
                })
            });

        visiting.remove(name);
        result
    }

    fn expression_is_constant_like(
        &self,
        expr: &Expression,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        if depth > 20 {
            return false;
        }
        match expr {
            Expression::Const(_) => true,
            Expression::UnaryOp { operand, .. } => {
                self.expression_is_constant_like(operand, visiting, depth + 1)
            }
            Expression::BinOp { lhs, rhs, .. } => {
                self.expression_is_constant_like(lhs, visiting, depth + 1)
                    && self.expression_is_constant_like(rhs, visiting, depth + 1)
            }
            Expression::Var(name) => {
                if !visiting.insert(name.clone()) {
                    return false;
                }
                let result = self
                    .var_name_to_def_pc
                    .get(name)
                    .and_then(|def_pc| self.expressions.get(def_pc))
                    .is_some_and(|def_expr| {
                        self.expression_is_constant_like(def_expr, visiting, depth + 1)
                    });
                visiting.remove(name);
                result
            }
            _ => false,
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
                VarType::U64 => "u64",
                VarType::I64 => "i64",
                VarType::U32 => "u32",
                VarType::I32 => "i32",
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn format_pc(&mut self, pc: usize, instr: &Instruction) -> Option<String> {
        if self.eliminated_pcs.contains(&pc) {
            return None;
        }

        // Format the expression without `let` prefix first, then add `let` if needed.
        let (raw_line, declare_var) = self.format_pc_raw(pc, instr)?;

        // Add `let` prefix on first declaration of a variable.
        if let Some(var_name) = declare_var
            && self.declared_vars.insert(var_name)
        {
            return Some(format!("let {}", raw_line));
        }
        Some(raw_line)
    }

    /// Format an instruction without declaration tracking.
    /// Returns the formatted line and optionally the variable name to declare.
    pub fn format_pc_raw(
        &self,
        pc: usize,
        instr: &Instruction,
    ) -> Option<(String, Option<String>)> {
        let ctx = self.format_context();
        let expr = self.expressions.get(&pc)?;
        let dst_name = self.def_var_name_with_type(pc, instr).map(|(name, _)| name);

        match expr {
            Expression::Raw(s) => Some((s.clone(), None)),
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
                    return Some((
                        format!("{} = {}", slot_name, format_expression(value, &ctx)),
                        Some(slot_name.clone()),
                    ));
                }
                if let Some(name) = resolve_named_global(base, *offset, *width, &ctx) {
                    Some((
                        format!("{} = {}", name, format_expression(value, &ctx)),
                        None,
                    ))
                } else if let Some(mem_access) = format_mem_base_access(base, *offset, *width, &ctx)
                {
                    Some((
                        format!("{} = {}", mem_access, format_expression(value, &ctx)),
                        None,
                    ))
                } else if let Some(field) = format_struct_field(base, *offset, *width, &ctx) {
                    Some((
                        format!("{} = {}", field, format_expression(value, &ctx)),
                        None,
                    ))
                } else if let Some(arr) = format_array_access(base, *offset, *width, &ctx) {
                    Some((
                        format!("{} = {}", arr, format_expression(value, &ctx)),
                        None,
                    ))
                } else {
                    Some((
                        format!(
                            "{}[{}] = {}",
                            width,
                            format_mem_address(base, *offset, &ctx),
                            format_expression(value, &ctx)
                        ),
                        None,
                    ))
                }
            }
            Expression::Call { name, args } => {
                let arg_strs: Vec<String> =
                    args.iter().map(|a| format_expression(a, &ctx)).collect();
                let call = format!("{}({})", name, arg_strs.join(", "));
                if let Some(dst) = dst_name {
                    Some((format!("{} = {}", dst, call), Some(dst)))
                } else {
                    Some((call, None))
                }
            }
            _ => {
                if let Some(dst) = dst_name {
                    Some((
                        format!("{} = {}", dst, format_expression(expr, &ctx)),
                        Some(dst),
                    ))
                } else {
                    Some((format_expression(expr, &ctx), None))
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
        let def_pc = self.var_name_to_def_pc.get(var_name)?;
        self.expressions.get(def_pc)
    }

    /// Returns true when `var_name` is a synthetic boolean temporary at `def_pc`.
    /// These are safe candidates for branch-condition inlining/elimination.
    pub fn is_synthetic_boolean_temp(&self, var_name: &str, def_pc: usize) -> bool {
        let bool_typed_at_def = self.variables.iter().any(|(&(pc, _), var)| {
            pc == def_pc && var.name == var_name && matches!(var.var_type, VarType::Boolean)
        });
        if !bool_typed_at_def {
            return false;
        }

        self.expression_for_var(var_name)
            .is_some_and(is_boolean_expr)
    }

    /// Recursively resolve eliminated variable references in an expression.
    /// When a `Var(name)` refers to a variable whose definition was eliminated
    /// (inlined elsewhere), substitute the variable's definition expression.
    pub fn resolve_eliminated_vars(&self, expr: &Expression) -> Expression {
        self.resolve_eliminated_vars_depth(expr, 0)
    }

    fn resolve_eliminated_vars_depth(&self, expr: &Expression, depth: usize) -> Expression {
        if depth > 10 {
            return expr.clone();
        }
        match expr {
            Expression::Var(name) => {
                if let Some(def_pc) = self.var_name_to_def_pc.get(name.as_str())
                    && self.eliminated_pcs.contains(def_pc)
                    && let Some(def_expr) = self.expressions.get(def_pc)
                {
                    self.resolve_eliminated_vars_depth(def_expr, depth + 1)
                } else {
                    expr.clone()
                }
            }
            Expression::BinOp { op, lhs, rhs } => Expression::BinOp {
                op: *op,
                lhs: Box::new(self.resolve_eliminated_vars_depth(lhs, depth)),
                rhs: Box::new(self.resolve_eliminated_vars_depth(rhs, depth)),
            },
            Expression::UnaryOp { op, operand } => Expression::UnaryOp {
                op: *op,
                operand: Box::new(self.resolve_eliminated_vars_depth(operand, depth)),
            },
            Expression::Load {
                width,
                base,
                offset,
            } => Expression::Load {
                width: *width,
                base: Box::new(self.resolve_eliminated_vars_depth(base, depth)),
                offset: *offset,
            },
            Expression::Store {
                width,
                base,
                offset,
                value,
            } => Expression::Store {
                width: *width,
                base: Box::new(self.resolve_eliminated_vars_depth(base, depth)),
                offset: *offset,
                value: Box::new(self.resolve_eliminated_vars_depth(value, depth)),
            },
            Expression::Call { name, args } => Expression::Call {
                name: name.clone(),
                args: args
                    .iter()
                    .map(|a| self.resolve_eliminated_vars_depth(a, depth))
                    .collect(),
            },
            Expression::Const(_) | Expression::Raw(_) => expr.clone(),
        }
    }
}

/// Recursively simplify an expression by folding identity operations.
/// Map an ecalli index to a human-readable host function name.
/// Based on the JAM Graypaper specification (Appendix B).
fn ecalli_name(index: u32) -> String {
    match index {
        0 => "gas_remaining".into(),
        1 => "fetch".into(),
        2 => "lookup".into(),
        3 => "read".into(),
        4 => "write".into(),
        5 => "info".into(),
        6 => "historical_lookup".into(),
        7 => "export".into(),
        8 => "machine".into(),
        9 => "peek".into(),
        10 => "poke".into(),
        11 => "pages".into(),
        12 => "invoke".into(),
        13 => "expunge".into(),
        14 => "bless".into(),
        15 => "assign".into(),
        16 => "designate".into(),
        17 => "checkpoint".into(),
        18 => "new_service".into(),
        19 => "upgrade".into(),
        20 => "transfer".into(),
        21 => "eject".into(),
        22 => "query".into(),
        23 => "solicit".into(),
        24 => "forget".into(),
        25 => "yield_".into(),
        26 => "provide".into(),
        100 => "log".into(),
        _ => format!("ecalli({})", index),
    }
}

/// - `x + 0`, `x - 0`, `x | 0`, `x ^ 0`, `x << 0`, `x >>u 0`, `x >>s 0` → `x`
/// - `x * 1`, `x /u 1`, `x /s 1` → `x`
/// - `x * 0`, `x & 0` → `0`
/// - `bool <u 1` → `!bool` (common negation pattern)
///
/// Returns true if an expression is known to produce a boolean (0 or 1) result.
/// Used to elide `!= 0` checks on expressions that are already boolean.
pub fn is_boolean_expr(expr: &Expression) -> bool {
    match expr {
        Expression::UnaryOp {
            op: UnaryOp::Not, ..
        } => true,
        Expression::BinOp { op, lhs, rhs } => {
            if matches!(
                op,
                BinOp::LtU
                    | BinOp::LtS
                    | BinOp::GeU
                    | BinOp::GeS
                    | BinOp::GtU
                    | BinOp::GtS
                    | BinOp::LeU
                    | BinOp::LeS
            ) {
                return true;
            }
            // Bitwise AND/OR of two booleans is also boolean
            if matches!(op, BinOp::And | BinOp::Or) {
                return is_boolean_expr(lhs) && is_boolean_expr(rhs);
            }
            false
        }
        _ => false,
    }
}

pub fn simplify_expression(expr: Expression) -> Expression {
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
                // 0 <u expr → expr when expr is already boolean (comparison or negation)
                // This eliminates truthy checks like `0 <u (x >=u y)` → `x >=u y`
                (BinOp::LtU, Expression::Const(0), _) if is_boolean_expr(&rhs) => rhs,
                // Flip `const <u expr` → `expr >u const` and `const <s expr` → `expr >s const`
                // for readability (e.g., `1 <s x` → `x >s 1`).
                // Skip constant 0 for LtU since `0 <u expr` is handled by format_expression
                // as `expr != 0` (which reads better than `expr >u 0`).
                (BinOp::LtU, Expression::Const(0), _) => Expression::BinOp {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                (BinOp::LtU | BinOp::LtS, Expression::Const(_), _) => {
                    let gt_op = if op == BinOp::LtU {
                        BinOp::GtU
                    } else {
                        BinOp::GtS
                    };
                    Expression::BinOp {
                        op: gt_op,
                        lhs: Box::new(rhs),
                        rhs: Box::new(lhs),
                    }
                }
                _ => Expression::BinOp {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
            }
        }
        Expression::UnaryOp { op, operand } => {
            let operand = simplify_expression(*operand);
            if op == UnaryOp::Not {
                // Double negation elimination: !!x → x
                if let Expression::UnaryOp {
                    op: UnaryOp::Not,
                    operand: inner,
                } = operand
                {
                    return *inner;
                }
                // Comparison inversion: !(x <u y) → x >=u y, !(x <s y) → x >=s y
                if let Expression::BinOp {
                    op:
                        cmp_op @ (BinOp::LtU
                        | BinOp::LtS
                        | BinOp::GtU
                        | BinOp::GtS
                        | BinOp::GeU
                        | BinOp::GeS
                        | BinOp::LeU
                        | BinOp::LeS),
                    lhs,
                    rhs,
                } = operand
                {
                    // Invert comparison: !(a < b) → a >= b, !(a > b) → a <= b, !(a >= b) → a < b
                    let (inverted, new_lhs, new_rhs) = match cmp_op {
                        BinOp::LtU => (BinOp::GeU, lhs, rhs),
                        BinOp::LtS => (BinOp::GeS, lhs, rhs),
                        BinOp::GtU => (BinOp::LeU, lhs, rhs), // !(a >u b) → a <=u b
                        BinOp::GtS => (BinOp::LeS, lhs, rhs), // !(a >s b) → a <=s b
                        BinOp::GeU => (BinOp::LtU, lhs, rhs), // !(a >=u b) → a <u b
                        BinOp::GeS => (BinOp::LtS, lhs, rhs), // !(a >=s b) → a <s b
                        BinOp::LeU => (BinOp::GtU, lhs, rhs), // !(a <=u b) → a >u b
                        BinOp::LeS => (BinOp::GtS, lhs, rhs), // !(a <=s b) → a >s b
                        _ => unreachable!(),
                    };
                    return Expression::BinOp {
                        op: inverted,
                        lhs: new_lhs,
                        rhs: new_rhs,
                    };
                }
            }
            Expression::UnaryOp {
                op,
                operand: Box::new(operand),
            }
        }
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

/// Collect all variable names referenced in an expression.
fn collect_var_names(expr: &Expression, names: &mut HashSet<String>) {
    match expr {
        Expression::Var(n) => {
            names.insert(n.clone());
        }
        Expression::Const(_) | Expression::Raw(_) => {}
        Expression::BinOp { lhs, rhs, .. } => {
            collect_var_names(lhs, names);
            collect_var_names(rhs, names);
        }
        Expression::UnaryOp { operand, .. } => {
            collect_var_names(operand, names);
        }
        Expression::Load { base, .. } => {
            collect_var_names(base, names);
        }
        Expression::Store { base, value, .. } => {
            collect_var_names(base, names);
            collect_var_names(value, names);
        }
        Expression::Call { args, .. } => {
            for arg in args {
                collect_var_names(arg, names);
            }
        }
    }
}

/// Build an index: variable name -> set of PCs whose expression references it.
/// Also includes PCs from var_at_use for Raw expressions and branch-only uses.
fn build_var_use_index(
    expressions: &HashMap<usize, Expression>,
    var_at_use: &HashMap<(usize, u8), String>,
    eliminated_pcs: &HashSet<usize>,
) -> HashMap<String, HashSet<usize>> {
    let mut index: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut names_buf = HashSet::new();

    for (&pc, expr) in expressions {
        if eliminated_pcs.contains(&pc) {
            continue;
        }
        names_buf.clear();
        collect_var_names(expr, &mut names_buf);
        for name in &names_buf {
            index.entry(name.clone()).or_default().insert(pc);
        }
    }

    // Add var_at_use entries for PCs without expression entries (branch conditions)
    // or with Raw expressions (where variable names are embedded as strings and
    // not captured by collect_var_names).
    for (&(upc, _), name) in var_at_use {
        if eliminated_pcs.contains(&upc) {
            continue;
        }
        let needs_var_at_use = match expressions.get(&upc) {
            None => true,                     // no expression at all
            Some(Expression::Raw(_)) => true, // Raw doesn't contain Var nodes
            _ => false,
        };
        if needs_var_at_use {
            index.entry(name.clone()).or_default().insert(upc);
        }
    }

    index
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

/// Apply multiple variable renames in a single traversal of an expression tree.
fn rename_vars_multi(expr: &mut Expression, rename_map: &HashMap<String, String>) {
    match expr {
        Expression::Var(n) => {
            if let Some(new_name) = rename_map.get(n.as_str()) {
                *n = new_name.clone();
            }
        }
        Expression::Const(_) | Expression::Raw(_) => {}
        Expression::BinOp { lhs, rhs, .. } => {
            rename_vars_multi(lhs, rename_map);
            rename_vars_multi(rhs, rename_map);
        }
        Expression::UnaryOp { operand, .. } => {
            rename_vars_multi(operand, rename_map);
        }
        Expression::Load { base, .. } => {
            rename_vars_multi(base, rename_map);
        }
        Expression::Store { base, value, .. } => {
            rename_vars_multi(base, rename_map);
            rename_vars_multi(value, rename_map);
        }
        Expression::Call { args, .. } => {
            for arg in args {
                rename_vars_multi(arg, rename_map);
            }
        }
    }
}

/// Rename all occurrences of `Var(old_name)` to `Var(new_name)` in-place.
#[cfg_attr(not(test), allow(dead_code))]
fn rename_var_in_expression(expr: &mut Expression, old_name: &str, new_name: &str) {
    match expr {
        Expression::Var(n) if n == old_name => *n = new_name.to_string(),
        Expression::Var(_) | Expression::Const(_) | Expression::Raw(_) => {}
        Expression::BinOp { lhs, rhs, .. } => {
            rename_var_in_expression(lhs, old_name, new_name);
            rename_var_in_expression(rhs, old_name, new_name);
        }
        Expression::UnaryOp { operand, .. } => {
            rename_var_in_expression(operand, old_name, new_name);
        }
        Expression::Load { base, .. } => {
            rename_var_in_expression(base, old_name, new_name);
        }
        Expression::Store { base, value, .. } => {
            rename_var_in_expression(base, old_name, new_name);
            rename_var_in_expression(value, old_name, new_name);
        }
        Expression::Call { args, .. } => {
            for arg in args {
                rename_var_in_expression(arg, old_name, new_name);
            }
        }
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
fn collect_live_loads(expr: &Expression, ctx: &FormatContext, live: &mut HashSet<(String, i32)>) {
    match expr {
        Expression::Load { base, offset, .. } => {
            live.insert((format_expression(base, ctx), *offset));
            collect_live_loads(base, ctx, live);
        }
        Expression::BinOp { lhs, rhs, .. } => {
            collect_live_loads(lhs, ctx, live);
            collect_live_loads(rhs, ctx, live);
        }
        Expression::UnaryOp { operand, .. } => {
            collect_live_loads(operand, ctx, live);
        }
        Expression::Store { base, value, .. } => {
            collect_live_loads(base, ctx, live);
            collect_live_loads(value, ctx, live);
        }
        Expression::Call { args, .. } => {
            for arg in args {
                collect_live_loads(arg, ctx, live);
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

/// Format an integer constant: use hex for large values (|v| >= 0x1000), decimal otherwise.
fn format_const(v: i64) -> String {
    if v >= 0x1000 {
        format!("0x{:X}", v)
    } else if v <= -0x1000 {
        // Use wrapping_neg to avoid overflow on i64::MIN, then format as unsigned hex.
        format!("-0x{:X}", (v as u64).wrapping_neg())
    } else {
        format!("{}", v)
    }
}

/// Format an Expression tree as a human-readable string with minimal parentheses.
pub fn format_expression(expr: &Expression, ctx: &FormatContext) -> String {
    match expr {
        Expression::Const(v) => format_const(*v),
        Expression::Var(name) => name.clone(),
        Expression::Raw(s) => s.clone(),
        Expression::BinOp { op, lhs, rhs } => {
            // Convert `x + -N` to `x - N`, and simplify memory base subtractions.
            if *op == BinOp::Add
                && let Expression::Const(v) = rhs.as_ref()
                && *v < 0
            {
                // If subtracting the memory base, this converts PVM addr → WASM offset
                if let Some(mem_base) = ctx.memory_base
                    && (-*v) as u64 == mem_base
                {
                    let lhs_str = format_expression(lhs, ctx);
                    return format!("wasm_ptr({})", lhs_str);
                }
                // If subtracting the linear memory offset, strip it entirely —
                // the matching *ptr dereference already hides the addition.
                if let Some(lmo) = ctx.linear_memory_offset
                    && ctx.deref_context
                    && (-*v) as u64 == lmo
                {
                    return format_expression(lhs, ctx);
                }
                let lhs_str = format_expression_maybe_parens(lhs, BinOp::Sub, true, ctx);
                return format!("{} - {}", lhs_str, format_const(-v));
            }
            // Simplify `x + MEMORY_BASE` (converting WASM offset → PVM address)
            if *op == BinOp::Add
                && let Expression::Const(v) = rhs.as_ref()
                && *v > 0
                && let Some(mem_base) = ctx.memory_base
                && *v as u64 == mem_base
            {
                let lhs_str = format_expression(lhs, ctx);
                return format!("pvm_addr({})", lhs_str);
            }
            if *op == BinOp::Add
                && let Expression::Const(v) = lhs.as_ref()
                && *v > 0
                && let Some(mem_base) = ctx.memory_base
                && *v as u64 == mem_base
            {
                let rhs_str = format_expression(rhs, ctx);
                return format!("pvm_addr({})", rhs_str);
            }
            // Convert `0 <u (a | b)` to `(a | b) != 0` for non-boolean expressions.
            // This makes bitwise boolean patterns more readable.
            if *op == BinOp::LtU
                && matches!(lhs.as_ref(), Expression::Const(0))
                && !is_boolean_expr(rhs)
            {
                let rhs_str = format_expression(rhs, ctx);
                // Wrap in parens if the rhs is a binary operation to avoid precedence issues
                let rhs_str = if matches!(rhs.as_ref(), Expression::BinOp { .. }) {
                    format!("({})", rhs_str)
                } else {
                    rhs_str
                };
                return format!("{} != 0", rhs_str);
            }
            let lhs_str = format_expression_maybe_parens(lhs, *op, true, ctx);
            let rhs_str = format_expression_maybe_parens(rhs, *op, false, ctx);
            format!("{} {} {}", lhs_str, op, rhs_str)
        }
        Expression::UnaryOp { op, operand } => {
            format!("{}({})", op, format_expression(operand, ctx))
        }
        Expression::Load {
            width,
            base,
            offset,
        } => {
            if let Some(name) = resolve_named_global(base, *offset, *width, ctx) {
                name
            } else if let Some(mem_access) = format_mem_base_access(base, *offset, *width, ctx) {
                mem_access
            } else if let Some(field) = format_struct_field(base, *offset, *width, ctx) {
                field
            } else if let Some(arr) = format_array_access(base, *offset, *width, ctx) {
                arr
            } else {
                format!("{}[{}]", width, format_mem_address(base, *offset, ctx))
            }
        }
        Expression::Store {
            width,
            base,
            offset,
            value,
        } => {
            if let Some(name) = resolve_named_global(base, *offset, *width, ctx) {
                format!("{} = {}", name, format_expression(value, ctx))
            } else if let Some(mem_access) = format_mem_base_access(base, *offset, *width, ctx) {
                format!("{} = {}", mem_access, format_expression(value, ctx))
            } else if let Some(field) = format_struct_field(base, *offset, *width, ctx) {
                format!("{} = {}", field, format_expression(value, ctx))
            } else if let Some(arr) = format_array_access(base, *offset, *width, ctx) {
                format!("{} = {}", arr, format_expression(value, ctx))
            } else {
                format!(
                    "{}[{}] = {}",
                    width,
                    format_mem_address(base, *offset, ctx),
                    format_expression(value, ctx)
                )
            }
        }
        Expression::Call { name, args } => {
            let arg_strs: Vec<String> = args.iter().map(|a| format_expression(a, ctx)).collect();
            format!("{}({})", name, arg_strs.join(", "))
        }
    }
}

/// Detect if a Load/Store base expression references linear memory via MEMORY_BASE
/// and simplify it to a width-preserving memory access.
/// For example, `u8[var_61 + 0x50000]` → `u8[var_61]` when memory_base = 0x50000.
fn format_mem_base_access(
    base: &Expression,
    offset: i32,
    width: MemWidth,
    ctx: &FormatContext,
) -> Option<String> {
    let mem_base = ctx.memory_base? as i64;
    let deref_ctx = ctx.with_deref_context();

    // Pattern 1: base = BinOp(var, Add, Const(MEMORY_BASE)), offset = 0
    if offset == 0
        && let Expression::BinOp {
            op: BinOp::Add,
            lhs,
            rhs,
        } = base
    {
        if let Expression::Const(v) = rhs.as_ref()
            && *v == mem_base
        {
            return Some(format!("{}[{}]", width, format_expression(lhs, &deref_ctx)));
        }
        if let Expression::Const(v) = lhs.as_ref()
            && *v == mem_base
        {
            return Some(format!("{}[{}]", width, format_expression(rhs, &deref_ctx)));
        }
    }

    // Pattern 2: base = var, offset = MEMORY_BASE (e.g., LoadInd { base: var, offset: 0x50000 })
    // For pointer variables with linear_memory_offset, render as *ptr dereference.
    if let Some(lmo) = ctx.linear_memory_offset
        && offset as u64 == lmo
        && let Expression::Var(name) = base
        && name.starts_with("ptr_")
    {
        return Some(format!("*{}", name));
    }
    // Preserve the access width in the rendered syntax.
    if offset as i64 == mem_base {
        return Some(format!(
            "{}[{}]",
            width,
            format_expression(base, &deref_ctx)
        ));
    }

    None
}

/// Format a pointer dereference as a struct field access if the base is a pointer variable.
/// Returns `Some("ptr->field_N")` for pointer bases, `None` otherwise.
fn format_struct_field(
    base: &Expression,
    offset: i32,
    _width: MemWidth,
    ctx: &FormatContext,
) -> Option<String> {
    if let Expression::Var(name) = base
        && name.starts_with("ptr_")
        && offset >= 0
    {
        // Check linear memory offset first (e.g., 0x50000 for AS programs)
        if let Some(lmo) = ctx.linear_memory_offset
            && offset as u64 == lmo
        {
            return Some(format!("*{}", name));
        }
        // Check memory_base (for non-AS programs)
        if let Some(mem_base) = ctx.memory_base
            && offset as u64 == mem_base
        {
            return Some(format!("*{}", name));
        }
        return Some(format!("{}->field_{}", name, offset));
    }
    None
}

/// Detect array access patterns: `base + index * element_size` where element_size
/// matches the load/store width. Returns `Some("base[index]")` on match.
///
/// Recognized patterns (with offset == 0):
/// - `ptr + index * N` where N == width.byte_size() → `ptr[index]`
/// - `index * N + ptr` (commutative) → `ptr[index]`
///
/// Byte-width accesses (u8/i8) are excluded because `base + index * 1` doesn't
/// clearly indicate array semantics.
fn format_array_access(
    base: &Expression,
    offset: i32,
    width: MemWidth,
    ctx: &FormatContext,
) -> Option<String> {
    // Only match when the constant offset is zero (the index handles all addressing)
    if offset != 0 {
        return None;
    }
    let elem_size = width.byte_size();
    // Skip byte-width accesses — `base + index * 1` is just `base + index`,
    // which doesn't clearly indicate array semantics.
    if elem_size <= 1 {
        return None;
    }

    // Pattern: base = ptr + index * element_size
    if let Expression::BinOp {
        op: BinOp::Add,
        lhs: ptr,
        rhs: index_expr,
    } = base
    {
        // rhs = index * Const(elem_size)
        if let Expression::BinOp {
            op: BinOp::Mul,
            lhs: index,
            rhs: multiplier,
        } = index_expr.as_ref()
            && let Expression::Const(m) = multiplier.as_ref()
            && *m == elem_size
        {
            return Some(format!(
                "{}[{}]",
                format_expression(ptr, ctx),
                format_expression(index, ctx)
            ));
        }
        // Also match: lhs = index * element_size, rhs = ptr (commutative Add)
        if let Expression::BinOp {
            op: BinOp::Mul,
            lhs: index,
            rhs: multiplier,
        } = ptr.as_ref()
            && let Expression::Const(m) = multiplier.as_ref()
            && *m == elem_size
        {
            return Some(format!(
                "{}[{}]",
                format_expression(index_expr, ctx),
                format_expression(index, ctx)
            ));
        }
    }

    None
}

/// Resolve a known PVM/AssemblyScript global address to a named constant.
/// Returns `Some("GLOBAL_NAME")` if the absolute address matches a known global.
fn resolve_named_global(
    base: &Expression,
    offset: i32,
    width: MemWidth,
    ctx: &FormatContext,
) -> Option<String> {
    // Compute absolute address from base + offset
    let addr = match base {
        Expression::Const(b) => (*b).wrapping_add(offset as i64),
        _ if offset == 0 => return None, // Non-constant base, can't resolve
        _ => return None,
    };

    match addr {
        0x30000 => Some("RESULT_PTR".to_string()),
        0x30004 => Some("RESULT_LEN".to_string()),
        0x30008 => Some("HEAP_PTR".to_string()),
        0x3000C => Some("HEAP_PAGES".to_string()),
        _ => {
            // Check if address falls within linear memory (>= memory_base)
            if let Some(mem_base) = ctx.memory_base {
                let mem_base_i64 = mem_base as i64;
                if addr >= mem_base_i64 {
                    let wasm_offset = addr - mem_base_i64;
                    return Some(format!("{}[{}]", width, format_const(wasm_offset)));
                }
            }
            None
        }
    }
}

/// Format a memory address `base + offset` with clean output.
fn format_mem_address(base: &Expression, offset: i32, ctx: &FormatContext) -> String {
    let deref_ctx = ctx.with_deref_context();
    match (base, offset) {
        // Pure constant address: base is 0 → just show offset
        (Expression::Const(0), off) => format_const(off as i64),
        // Constant base + offset → fold them
        (Expression::Const(b), off) => format_const((*b).wrapping_add(off as i64)),
        // Zero offset → just base
        (_, 0) => format_expression(base, &deref_ctx),
        // Negative offset
        (_, off) if off < 0 => format!(
            "{} - {}",
            format_expression(base, &deref_ctx),
            format_const((-off) as i64)
        ),
        // Positive offset
        (_, off) => format!(
            "{} + {}",
            format_expression(base, &deref_ctx),
            format_const(off as i64)
        ),
    }
}

/// Format a sub-expression, adding parentheses only when needed for precedence.
fn format_expression_maybe_parens(
    expr: &Expression,
    parent_op: BinOp,
    is_left: bool,
    ctx: &FormatContext,
) -> String {
    match expr {
        Expression::BinOp { op, .. } => {
            let child_prec = op_precedence(*op);
            let parent_prec = op_precedence(parent_op);
            // Parenthesise if child binds looser than parent.
            // For right-hand operands of non-commutative ops (sub, div, rem),
            // also parenthesise when precedences are equal to preserve
            // left-to-right evaluation: a - (b - c) != a - b - c.
            let needs_parens = if child_prec < parent_prec {
                true
            } else if child_prec == parent_prec && !is_left {
                // Same precedence on the right: only safe without parens
                // for commutative operators.
                !is_commutative(parent_op)
            } else {
                false
            };
            if needs_parens {
                format!("({})", format_expression(expr, ctx))
            } else {
                format_expression(expr, ctx)
            }
        }
        _ => format_expression(expr, ctx),
    }
}

fn is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

/// Simple operator precedence (higher = binds tighter).
fn op_precedence(op: BinOp) -> u8 {
    match op {
        BinOp::Or | BinOp::OrInv => 1,
        BinOp::Xor | BinOp::Xnor => 2,
        BinOp::And | BinOp::AndInv => 3,
        BinOp::LtU
        | BinOp::LtS
        | BinOp::GeU
        | BinOp::GeS
        | BinOp::GtU
        | BinOp::GtS
        | BinOp::LeU
        | BinOp::LeS
        | BinOp::Max
        | BinOp::MaxU
        | BinOp::Min
        | BinOp::MinU => 4,
        BinOp::Shl | BinOp::ShrU | BinOp::ShrS | BinOp::RotL | BinOp::RotR => 5,
        BinOp::Add | BinOp::Sub | BinOp::NegAdd => 6,
        BinOp::Mul
        | BinOp::DivU
        | BinOp::DivS
        | BinOp::RemU
        | BinOp::RemS
        | BinOp::MulUpperSS
        | BinOp::MulUpperUU
        | BinOp::MulUpperSU => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_test_cfg;
    use crate::dataflow::DataFlowAnalysis;

    /// Default formatting context for tests (no memory base).
    fn ctx() -> FormatContext {
        FormatContext::default()
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

        // PC 4's expression should be the folded result: 42 + 1 = 43.
        let expr = lifted.expressions.get(&4).unwrap();
        let formatted = format_expression(expr, &ctx());
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
    fn test_signedness_type_inference() {
        // r2 = r0 /s r1 → r2 should be I64 (signed 64-bit)
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::DivS64 {
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
        assert_eq!(
            var.var_type,
            VarType::I64,
            "DivS64 result should be I64, got: {}",
            var.var_type
        );
    }

    #[test]
    fn test_width_type_inference() {
        // r2 = r0 + r1 (32-bit) → r2 should be U32
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::Add32 {
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
        assert_eq!(
            var.var_type,
            VarType::U32,
            "Add32 result should be U32, got: {}",
            var.var_type
        );
    }

    #[test]
    fn test_simplify_add_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x");
    }

    #[test]
    fn test_simplify_xor_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Xor,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x");
    }

    #[test]
    fn test_simplify_mul_one() {
        let expr = Expression::BinOp {
            op: BinOp::Mul,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x");
    }

    #[test]
    fn test_simplify_mul_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Mul,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "0");
    }

    #[test]
    fn test_simplify_and_zero() {
        let expr = Expression::BinOp {
            op: BinOp::And,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "0");
    }

    #[test]
    fn test_simplify_ltu_1_negation() {
        let expr = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Var("cond_0".to_string())),
            rhs: Box::new(Expression::Const(1)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "!(cond_0)");
    }

    #[test]
    fn test_simplify_double_negation() {
        // !!x → x
        let expr = Expression::UnaryOp {
            op: UnaryOp::Not,
            operand: Box::new(Expression::UnaryOp {
                op: UnaryOp::Not,
                operand: Box::new(Expression::Var("cond_0".to_string())),
            }),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "cond_0");
    }

    #[test]
    fn test_simplify_comparison_inversion() {
        // !(x <u y) → x >=u y
        let expr = Expression::UnaryOp {
            op: UnaryOp::Not,
            operand: Box::new(Expression::BinOp {
                op: BinOp::LtU,
                lhs: Box::new(Expression::Var("x".to_string())),
                rhs: Box::new(Expression::Var("y".to_string())),
            }),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x >=u y");

        // !(a <s b) → a >=s b
        let expr_signed = Expression::UnaryOp {
            op: UnaryOp::Not,
            operand: Box::new(Expression::BinOp {
                op: BinOp::LtS,
                lhs: Box::new(Expression::Var("a".to_string())),
                rhs: Box::new(Expression::Var("b".to_string())),
            }),
        };
        let simplified_signed = simplify_expression(expr_signed);
        assert_eq!(format_expression(&simplified_signed, &ctx()), "a >=s b");

        // !(x >s y) → x <=s y
        let expr_gt = Expression::UnaryOp {
            op: UnaryOp::Not,
            operand: Box::new(Expression::BinOp {
                op: BinOp::GtS,
                lhs: Box::new(Expression::Var("x".to_string())),
                rhs: Box::new(Expression::Var("y".to_string())),
            }),
        };
        let simplified_gt = simplify_expression(expr_gt);
        assert_eq!(format_expression(&simplified_gt, &ctx()), "x <=s y");

        // !(x >=u y) → x <u y
        let expr_ge = Expression::UnaryOp {
            op: UnaryOp::Not,
            operand: Box::new(Expression::BinOp {
                op: BinOp::GeU,
                lhs: Box::new(Expression::Var("a".to_string())),
                rhs: Box::new(Expression::Var("b".to_string())),
            }),
        };
        let simplified_ge = simplify_expression(expr_ge);
        assert_eq!(format_expression(&simplified_ge, &ctx()), "a <u b");
    }

    #[test]
    fn test_simplify_0_ltu_boolean() {
        // 0 <u !(x <u y) → x >=u y
        // Chain: !(x <u y) → x >=u y, then 0 <u (x >=u y) → x >=u y
        let expr = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Const(0)),
            rhs: Box::new(Expression::UnaryOp {
                op: UnaryOp::Not,
                operand: Box::new(Expression::BinOp {
                    op: BinOp::LtU,
                    lhs: Box::new(Expression::Var("x".to_string())),
                    rhs: Box::new(Expression::Var("y".to_string())),
                }),
            }),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x >=u y");
    }

    #[test]
    fn test_simplify_0_ltu_comparison() {
        // 0 <u (x <u y) → (x <u y) (truthy check on comparison)
        let expr = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Const(0)),
            rhs: Box::new(Expression::BinOp {
                op: BinOp::LtU,
                lhs: Box::new(Expression::Var("x".to_string())),
                rhs: Box::new(Expression::Var("y".to_string())),
            }),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x <u y");
    }

    #[test]
    fn test_format_0_ltu_bitwise_or() {
        // 0 <u (a | b) → (a | b) != 0
        let expr = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Const(0)),
            rhs: Box::new(Expression::BinOp {
                op: BinOp::Or,
                lhs: Box::new(Expression::Var("a".to_string())),
                rhs: Box::new(Expression::Var("b".to_string())),
            }),
        };
        assert_eq!(format_expression(&expr, &ctx()), "(a | b) != 0");

        // 0 <u x → x != 0 (simple variable, no parens needed)
        let expr2 = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Const(0)),
            rhs: Box::new(Expression::Var("x".to_string())),
        };
        assert_eq!(format_expression(&expr2, &ctx()), "x != 0");
    }

    #[test]
    fn test_simplify_const_lt_flip() {
        // 1 <s x → x >s 1
        let expr = Expression::BinOp {
            op: BinOp::LtS,
            lhs: Box::new(Expression::Const(1)),
            rhs: Box::new(Expression::Var("x".to_string())),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x >s 1");

        // 5 <u x → x >u 5
        let expr2 = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Const(5)),
            rhs: Box::new(Expression::Var("x".to_string())),
        };
        let simplified2 = simplify_expression(expr2);
        assert_eq!(format_expression(&simplified2, &ctx()), "x >u 5");

        // 0 <s x → x >s 0
        let expr3 = Expression::BinOp {
            op: BinOp::LtS,
            lhs: Box::new(Expression::Const(0)),
            rhs: Box::new(Expression::Var("x".to_string())),
        };
        let simplified3 = simplify_expression(expr3);
        assert_eq!(format_expression(&simplified3, &ctx()), "x >s 0");

        // 0 <u x → stays as-is (handled by format_expression as x != 0)
        let expr4 = Expression::BinOp {
            op: BinOp::LtU,
            lhs: Box::new(Expression::Const(0)),
            rhs: Box::new(Expression::Var("x".to_string())),
        };
        let simplified4 = simplify_expression(expr4);
        assert_eq!(format_expression(&simplified4, &ctx()), "x != 0");
    }

    #[test]
    fn test_simplify_shift_zero() {
        let expr = Expression::BinOp {
            op: BinOp::Shl,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(0)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x");
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
        assert_eq!(format_expression(&simplified, &ctx()), "x");
    }

    #[test]
    fn test_simplify_no_change() {
        let expr = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("x".to_string())),
            rhs: Box::new(Expression::Const(5)),
        };
        let simplified = simplify_expression(expr);
        assert_eq!(format_expression(&simplified, &ctx()), "x + 5");
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
        let formatted = format_expression(&expr, &ctx());
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
        let formatted = format_expression(&expr, &ctx());
        assert_eq!(formatted, "a * b + c");
    }

    #[test]
    fn test_format_expression_right_associativity() {
        // a - (b - c) must parenthesise the right operand because
        // subtraction is left-associative: a - b - c != a - (b - c)
        let expr = Expression::BinOp {
            op: BinOp::Sub,
            lhs: Box::new(Expression::Var("a".to_string())),
            rhs: Box::new(Expression::BinOp {
                op: BinOp::Sub,
                lhs: Box::new(Expression::Var("b".to_string())),
                rhs: Box::new(Expression::Var("c".to_string())),
            }),
        };
        let formatted = format_expression(&expr, &ctx());
        assert_eq!(formatted, "a - (b - c)");

        // a + (b + c) should NOT parenthesise — addition is commutative
        let expr2 = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("a".to_string())),
            rhs: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("b".to_string())),
                rhs: Box::new(Expression::Var("c".to_string())),
            }),
        };
        let formatted2 = format_expression(&expr2, &ctx());
        assert_eq!(formatted2, "a + b + c");
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
        let formatted = format_expression(expr, &ctx());
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
            format_expression(expr, &ctx())
        );
    }

    #[test]
    fn test_dead_store_elimination() {
        // r1 = 4096 (SP-like base); store u64[r1+8] = r2; store u64[r1+16] = r2; trap
        // Both stores are never loaded, so they should be eliminated as dead stack-slot stores.
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::LoadImm {
                            reg: 1,
                            value: 4096,
                        },
                    ),
                    (4, Instruction::LoadImm { reg: 2, value: 42 }),
                    (
                        8,
                        Instruction::StoreIndU64 {
                            base: 1,
                            src: 2,
                            offset: 8,
                        },
                    ),
                    (
                        12,
                        Instruction::StoreIndU64 {
                            base: 1,
                            src: 2,
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

        // r1 is used as a base in stores, so it should be inferred as a pointer (ptr_*).
        let var = lifted.variables.get(&(0, 1)).unwrap();
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
    fn test_dead_store_elimination_uses_shared_format_context_for_live_load_keys() {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: Some(0x50000),
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        };
        lifted.variables.insert(
            (1, 1),
            Variable {
                name: "ptr_0".to_string(),
                var_type: VarType::Pointer,
            },
        );
        lifted.var_name_to_def_pc.insert("ptr_0".to_string(), 1);
        lifted.expressions.insert(1, Expression::Const(0));

        let base_expr = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("ptr_0".to_string())),
            rhs: Box::new(Expression::Const(0x50000)),
        };
        lifted.expressions.insert(
            2,
            Expression::Store {
                width: MemWidth::U64,
                base: Box::new(base_expr.clone()),
                offset: 0,
                value: Box::new(Expression::Const(7)),
            },
        );
        lifted.expressions.insert(
            3,
            Expression::Load {
                width: MemWidth::U64,
                base: Box::new(base_expr),
                offset: 0,
            },
        );

        lifted.eliminate_dead_stores();

        assert!(
            !lifted.eliminated_pcs.contains(&2),
            "Store with matching live load should be retained when keying uses a shared context"
        );
    }

    #[test]
    fn test_store_load_forward_then_dead_store() {
        // r1 = 4096 (SP-like base); r2 = 7; store u64[r1+16] = r2; r3 = load u64[r1+16];
        // r3 = r2 + r4; store u64[r0+32] = r3; trap
        // r3 is used at PC 20 (different reg from r4), and r4 used at PC 20.
        // r1 has multiple uses (base in load/store), not constant-propagated.
        // r3 has uses at PC 20 and PC 24 (two distinct use sites via different instructions),
        // preventing fold. After forwarding, load at PC 12 replaced. After DSE, store at PC 8 removed.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (
                            0,
                            Instruction::LoadImm {
                                reg: 1,
                                value: 4096,
                            },
                        ),
                        (4, Instruction::LoadImm { reg: 2, value: 7 }),
                        (
                            8,
                            Instruction::StoreIndU64 {
                                base: 1,
                                src: 2,
                                offset: 16,
                            },
                        ),
                        (
                            12,
                            Instruction::LoadIndU64 {
                                dst: 3,
                                base: 1,
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
                                dst: 5,
                                src: 3,
                                value: 1,
                            },
                        ),
                        (
                            24,
                            Instruction::AddImm32 {
                                dst: 6,
                                src: 3,
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
                format_expression(e, &ctx())
            );
        }

        // The store at PC 8 should be eliminated (dead store after forwarding).
        assert!(
            lifted.eliminated_pcs.contains(&8),
            "Store at PC 8 should be a dead store after forwarding"
        );
    }

    #[test]
    fn test_dead_store_elimination_keeps_store_through_loaded_pointer() {
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::LoadImm {
                            reg: 1,
                            value: 4096,
                        },
                    ),
                    (
                        4,
                        Instruction::LoadImm {
                            reg: 2,
                            value: 8192,
                        },
                    ),
                    (
                        8,
                        Instruction::StoreIndU64 {
                            base: 1,
                            src: 2,
                            offset: 16,
                        },
                    ),
                    (
                        12,
                        Instruction::LoadIndU64 {
                            dst: 3,
                            base: 1,
                            offset: 16,
                        },
                    ),
                    (16, Instruction::LoadImm { reg: 4, value: 123 }),
                    (
                        20,
                        Instruction::StoreIndU64 {
                            base: 3,
                            src: 4,
                            offset: 0,
                        },
                    ),
                    (24, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        assert!(
            !lifted.eliminated_pcs.contains(&20),
            "Store through stack-loaded pointer must not be treated as dead stack-slot store"
        );
    }

    #[test]
    fn test_inline_let_declaration() {
        // r0 = 42; trap → should produce "let var_0 = 42"
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 42 }),
                    (4, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let line = lifted.format_pc(0, &Instruction::LoadImm { reg: 0, value: 42 });
        assert!(
            line.as_deref() == Some("let var_0 = 42"),
            "First use should have 'let' prefix: {:?}",
            line
        );
    }

    #[test]
    fn test_no_let_on_reassignment() {
        // r0 = 42; r0 = 99; trap → second assignment should NOT have 'let'
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 0, value: 42 }),
                    (4, Instruction::LoadImm { reg: 0, value: 99 }),
                    (8, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // First use: should have let
        let _ = lifted.format_pc(0, &Instruction::LoadImm { reg: 0, value: 42 });
        // Second use: should NOT have let (different def_pc creates a new variable)
        let line = lifted.format_pc(4, &Instruction::LoadImm { reg: 0, value: 99 });
        let line_str = line.as_deref().unwrap_or("");
        // The second definition creates a new variable (var_1), so it gets its own `let`
        assert!(
            line_str.starts_with("let "),
            "Second definition of r0 creates a new variable and should get 'let': {:?}",
            line_str
        );
    }

    #[test]
    fn test_trap_renders_as_return() {
        let cfg = build_test_cfg(0, vec![(0, vec![(0, Instruction::Trap)], vec![])]);
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let line = lifted.format_pc(0, &Instruction::Trap);
        assert_eq!(
            line.as_deref(),
            Some("return"),
            "Trap should be rendered as 'return': {:?}",
            line
        );
    }

    #[test]
    fn test_ecalli_named_host_functions() {
        assert_eq!(ecalli_name(0), "gas_remaining");
        assert_eq!(ecalli_name(3), "read");
        assert_eq!(ecalli_name(4), "write");
        assert_eq!(ecalli_name(17), "checkpoint");
        assert_eq!(ecalli_name(100), "log");
        assert_eq!(ecalli_name(999), "ecalli(999)");
    }

    #[test]
    fn test_ecalli_renders_named() {
        let instr = Instruction::Ecalli { index: 0 };
        let cfg = build_test_cfg(0, vec![(0, vec![(0, instr.clone())], vec![])]);
        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let line = lifted.format_pc(0, &instr);
        assert_eq!(
            line.as_deref(),
            Some("gas_remaining()"),
            "ecalli(0) should render as gas_remaining(): {:?}",
            line
        );
    }

    #[test]
    fn test_coalesce_variable() {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: None,
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        };

        // Set up two variables for the same register at different PCs
        lifted.variables.insert(
            (0, 0),
            Variable {
                name: "var_0".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.var_name_to_def_pc.insert("var_0".to_string(), 0);
        lifted.variables.insert(
            (30, 0),
            Variable {
                name: "var_2".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.var_name_to_def_pc.insert("var_2".to_string(), 30);

        // Set up var_at_use references
        lifted.var_at_use.insert((10, 0), "var_0".to_string()); // condition uses var_0
        lifted.var_at_use.insert((30, 0), "var_0".to_string()); // step uses var_0 as source
        lifted.var_at_use.insert((20, 0), "var_2".to_string()); // body uses var_2

        // Set up an expression that references var_2
        lifted.expressions.insert(
            30,
            Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("var_2".to_string())),
                rhs: Box::new(Expression::Const(1)),
            },
        );

        // Coalesce: rename var_2 → var_0
        lifted.coalesce_variable("var_2", "var_0");

        // Variable definition should be renamed
        assert_eq!(lifted.variables[&(30, 0)].name, "var_0");

        // var_at_use should be updated
        assert_eq!(lifted.var_at_use[&(20, 0)], "var_0");

        // Expression should have var_0 instead of var_2
        if let Expression::BinOp { lhs, .. } = &lifted.expressions[&30] {
            if let Expression::Var(name) = lhs.as_ref() {
                assert_eq!(name, "var_0", "Expression var should be coalesced");
            } else {
                panic!("Expected Var in lhs");
            }
        } else {
            panic!("Expected BinOp expression");
        }

        // Reverse index should map var_0 → 0 (old_name entry removed, new_name preserved)
        assert!(
            !lifted.var_name_to_def_pc.contains_key("var_2"),
            "Old name should be removed from reverse index"
        );
        // var_0 should still map (it was already there for def_pc 0)
        assert_eq!(lifted.var_name_to_def_pc["var_0"], 0);
    }

    #[test]
    fn test_expression_for_var_uses_reverse_index() {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: None,
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        };

        lifted.variables.insert(
            (10, 0),
            Variable {
                name: "var_0".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.var_name_to_def_pc.insert("var_0".to_string(), 10);
        lifted.expressions.insert(10, Expression::Const(42));

        // Should find the expression via the reverse index
        let expr = lifted.expression_for_var("var_0");
        assert!(expr.is_some());
        assert!(
            matches!(expr.unwrap(), Expression::Const(42)),
            "Should find expression via reverse index"
        );

        // Unknown variable should return None
        assert!(lifted.expression_for_var("unknown").is_none());
    }

    #[test]
    fn test_lower_ssa_to_lifted_uses_rewrites_instr_backed_use_names() {
        use crate::cfg::build_test_cfg;
        use crate::ir::ssa::SsaProgram;
        use crate::structuring::DominatorTree;
        use wasm_pvm::pvm::Instruction;

        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 1, value: 7 }),
                    (
                        4,
                        Instruction::Add32 {
                            dst: 2,
                            src1: 1,
                            src2: 0,
                        },
                    ),
                    (8, Instruction::Trap),
                ],
                vec![],
            )],
        );
        let dom_tree = DominatorTree::compute(&cfg);
        let ssa = SsaProgram::build(&cfg, &dom_tree);

        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: None,
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        };
        lifted.variables.insert(
            (0, 1),
            Variable {
                name: "var_0".to_string(),
                var_type: VarType::U64,
            },
        );
        // Deliberately wrong initial name for use-site (4, r1)
        lifted.var_at_use.insert((4, 1), "wrong_name".to_string());

        lifted.lower_ssa_to_lifted_uses(&ssa);
        assert_eq!(
            lifted.var_at_use.get(&(4, 1)).map(String::as_str),
            Some("var_0"),
            "SSA lowering should rewrite use-site to the concrete defining variable"
        );
    }

    #[test]
    fn test_is_synthetic_boolean_temp_requires_bool_type_and_boolean_expr() {
        let mut lifted = LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: None,
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        };

        lifted.variables.insert(
            (10, 0),
            Variable {
                name: "cond_0".to_string(),
                var_type: VarType::Boolean,
            },
        );
        lifted.var_name_to_def_pc.insert("cond_0".to_string(), 10);
        lifted.expressions.insert(
            10,
            Expression::BinOp {
                op: BinOp::LtU,
                lhs: Box::new(Expression::Var("var_a".to_string())),
                rhs: Box::new(Expression::Var("var_b".to_string())),
            },
        );

        assert!(lifted.is_synthetic_boolean_temp("cond_0", 10));

        // Same expression but non-boolean variable type -> should not qualify.
        lifted.variables.insert(
            (20, 1),
            Variable {
                name: "var_1".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.var_name_to_def_pc.insert("var_1".to_string(), 20);
        lifted.expressions.insert(
            20,
            Expression::BinOp {
                op: BinOp::LtU,
                lhs: Box::new(Expression::Var("var_x".to_string())),
                rhs: Box::new(Expression::Var("var_y".to_string())),
            },
        );
        assert!(!lifted.is_synthetic_boolean_temp("var_1", 20));
    }

    #[test]
    fn test_struct_field_access_formatting() {
        // Load from ptr_0 + 8 → ptr_0->field_8
        let load = Expression::Load {
            width: MemWidth::U64,
            base: Box::new(Expression::Var("ptr_0".to_string())),
            offset: 8,
        };
        assert_eq!(format_expression(&load, &ctx()), "ptr_0->field_8");

        // Load from ptr_0 + 0 → ptr_0->field_0
        let load_zero = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Var("ptr_0".to_string())),
            offset: 0,
        };
        assert_eq!(format_expression(&load_zero, &ctx()), "ptr_0->field_0");

        // Store to ptr_1 + 12 → ptr_1->field_12 = value
        let store = Expression::Store {
            width: MemWidth::U32,
            base: Box::new(Expression::Var("ptr_1".to_string())),
            offset: 12,
            value: Box::new(Expression::Var("var_0".to_string())),
        };
        assert_eq!(format_expression(&store, &ctx()), "ptr_1->field_12 = var_0");

        // Non-pointer base should NOT use struct notation
        let load_var = Expression::Load {
            width: MemWidth::U64,
            base: Box::new(Expression::Var("var_0".to_string())),
            offset: 8,
        };
        assert_eq!(format_expression(&load_var, &ctx()), "u64[var_0 + 8]");

        // Negative offset should NOT use struct notation
        let load_neg = Expression::Load {
            width: MemWidth::U64,
            base: Box::new(Expression::Var("ptr_0".to_string())),
            offset: -4,
        };
        assert_eq!(format_expression(&load_neg, &ctx()), "u64[ptr_0 - 4]");
    }

    #[test]
    fn test_array_access_formatting() {
        // u32 load: base + index * 4 → base[index]
        let load = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("ptr_0".to_string())),
                rhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("var_1".to_string())),
                    rhs: Box::new(Expression::Const(4)),
                }),
            }),
            offset: 0,
        };
        assert_eq!(format_expression(&load, &ctx()), "ptr_0[var_1]");

        // u64 load: base + index * 8 → base[index]
        let load64 = Expression::Load {
            width: MemWidth::U64,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("arr".to_string())),
                rhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("i".to_string())),
                    rhs: Box::new(Expression::Const(8)),
                }),
            }),
            offset: 0,
        };
        assert_eq!(format_expression(&load64, &ctx()), "arr[i]");

        // u16 load: base + index * 2 → base[index]
        let load16 = Expression::Load {
            width: MemWidth::U16,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("buf".to_string())),
                rhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("idx".to_string())),
                    rhs: Box::new(Expression::Const(2)),
                }),
            }),
            offset: 0,
        };
        assert_eq!(format_expression(&load16, &ctx()), "buf[idx]");

        // Wrong multiplier: u32 load with * 8 should NOT match
        let load_wrong = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("ptr_0".to_string())),
                rhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("var_1".to_string())),
                    rhs: Box::new(Expression::Const(8)),
                }),
            }),
            offset: 0,
        };
        assert_eq!(
            format_expression(&load_wrong, &ctx()),
            "u32[ptr_0 + var_1 * 8]"
        );

        // Non-zero offset: should NOT match array pattern
        let load_offset = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("ptr_0".to_string())),
                rhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("var_1".to_string())),
                    rhs: Box::new(Expression::Const(4)),
                }),
            }),
            offset: 8,
        };
        assert_eq!(
            format_expression(&load_offset, &ctx()),
            "u32[ptr_0 + var_1 * 4 + 8]"
        );

        // Store: base + index * 4 = value → base[index] = value
        let store = Expression::Store {
            width: MemWidth::U32,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("arr".to_string())),
                rhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("i".to_string())),
                    rhs: Box::new(Expression::Const(4)),
                }),
            }),
            offset: 0,
            value: Box::new(Expression::Const(42)),
        };
        assert_eq!(format_expression(&store, &ctx()), "arr[i] = 42");

        // Commutative: index * 4 + base → base[index]
        let load_comm = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::BinOp {
                    op: BinOp::Mul,
                    lhs: Box::new(Expression::Var("var_1".to_string())),
                    rhs: Box::new(Expression::Const(4)),
                }),
                rhs: Box::new(Expression::Var("ptr_0".to_string())),
            }),
            offset: 0,
        };
        assert_eq!(format_expression(&load_comm, &ctx()), "ptr_0[var_1]");

        // Byte-width (u8) should NOT trigger array pattern even with * 1
        let load_u8 = Expression::Load {
            width: MemWidth::U8,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("buf".to_string())),
                rhs: Box::new(Expression::Var("i".to_string())),
            }),
            offset: 0,
        };
        assert_eq!(format_expression(&load_u8, &ctx()), "u8[buf + i]");

        // Struct field access should take priority: ptr_ base with non-zero offset
        // is struct, not array (even if the base contains a multiply)
        let struct_load = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Var("ptr_0".to_string())),
            offset: 8,
        };
        assert_eq!(format_expression(&struct_load, &ctx()), "ptr_0->field_8");
    }

    #[test]
    fn test_indirect_call_resolution() {
        // JumpInd with a register holding a known function entry constant
        // resolve_indirect_call should find the function name
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::LoadImm {
                            reg: 5,
                            value: 0x200,
                        },
                    ),
                    (4, Instruction::JumpInd { reg: 5, offset: 0 }),
                ],
                vec![],
            )],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        // Register address 0x200 as a function
        lifted.call_targets.insert(0x200, "helper".to_string());

        // resolve_indirect_call should find the target
        let resolved = lifted.resolve_indirect_call(4, 5);
        assert_eq!(
            resolved.as_deref(),
            Some("helper"),
            "Should resolve indirect call to known function"
        );
    }

    #[test]
    fn test_indirect_call_unknown_target() {
        // JumpInd with an unknown target should render as call_indirect(var)
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (0, Instruction::LoadImm { reg: 3, value: 42 }),
                    (4, Instruction::JumpInd { reg: 3, offset: 0 }),
                ],
                vec![],
            )],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        // No call_targets set — resolve should return None

        let resolved = lifted.resolve_indirect_call(4, 3);
        assert!(resolved.is_none(), "Unknown target should not resolve");

        // The expression should be call_indirect
        let expr = lifted.expressions.get(&4);
        assert!(expr.is_some());
        let formatted = format_expression(expr.unwrap(), &ctx());
        assert!(
            formatted.contains("call_indirect"),
            "Unknown target should render as call_indirect: {}",
            formatted
        );
    }

    #[test]
    fn test_named_globals_in_load() {
        // resolve_named_global should return named constants for known PVM addresses
        let expr_heap_ptr = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Const(0x30008)),
            offset: 0,
        };
        assert_eq!(format_expression(&expr_heap_ptr, &ctx()), "HEAP_PTR");

        let expr_result_ptr = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Const(0x30000)),
            offset: 0,
        };
        assert_eq!(format_expression(&expr_result_ptr, &ctx()), "RESULT_PTR");

        let expr_result_len = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Const(0x30004)),
            offset: 0,
        };
        assert_eq!(format_expression(&expr_result_len, &ctx()), "RESULT_LEN");

        let expr_heap_pages = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Const(0x3000C)),
            offset: 0,
        };
        assert_eq!(format_expression(&expr_heap_pages, &ctx()), "HEAP_PAGES");
    }

    #[test]
    fn test_named_globals_in_store() {
        let expr = Expression::Store {
            width: MemWidth::U32,
            base: Box::new(Expression::Const(0x30008)),
            offset: 0,
            value: Box::new(Expression::Const(1036)),
        };
        assert_eq!(format_expression(&expr, &ctx()), "HEAP_PTR = 1036");
    }

    #[test]
    fn test_memory_base_simplification() {
        let ctx = FormatContext::new(Some(0x50000));

        // x + (-0x50000) → wasm_ptr(x)
        let expr = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("addr".to_string())),
            rhs: Box::new(Expression::Const(-0x50000)),
        };
        assert_eq!(format_expression(&expr, &ctx), "wasm_ptr(addr)");

        // x + 0x50000 → pvm_addr(x)
        let expr2 = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("offset".to_string())),
            rhs: Box::new(Expression::Const(0x50000)),
        };
        assert_eq!(format_expression(&expr2, &ctx), "pvm_addr(offset)");

        // ptr->field_0x50000 → u32[ptr] (linear memory access, width-preserving)
        let load = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Var("ptr_0".to_string())),
            offset: 0x50000,
        };
        assert_eq!(format_expression(&load, &ctx), "u32[ptr_0]");

        // u8[var + 0x50000] → u8[var]  (base is BinOp with memory base)
        let load2 = Expression::Load {
            width: MemWidth::U8,
            base: Box::new(Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("idx".to_string())),
                rhs: Box::new(Expression::Const(0x50000)),
            }),
            offset: 0,
        };
        assert_eq!(format_expression(&load2, &ctx), "u8[idx]");

        // u32[0] for constant address = memory base
        let load3 = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Const(0x50000)),
            offset: 0,
        };
        assert_eq!(format_expression(&load3, &ctx), "u32[0]");
    }

    #[test]
    fn test_linear_memory_offset_rendering_is_deref_only() {
        let mut ctx = FormatContext::new(None);
        ctx.linear_memory_offset = Some(0x50000);

        // Outside dereference context, keep arithmetic explicit.
        let arithmetic = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("addr".to_string())),
            rhs: Box::new(Expression::Const(-0x50000)),
        };
        assert_eq!(format_expression(&arithmetic, &ctx), "addr - 0x50000");

        // Pointer-like bases use dereference form when offset matches linear_memory_offset.
        let ptr_load = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Var("ptr_data".to_string())),
            offset: 0x50000,
        };
        assert_eq!(format_expression(&ptr_load, &ctx), "*ptr_data");

        // Non-pointer names should preserve arithmetic addressing.
        let non_ptr_load = Expression::Load {
            width: MemWidth::U32,
            base: Box::new(Expression::Var("idx".to_string())),
            offset: 0x50000,
        };
        assert_eq!(format_expression(&non_ptr_load, &ctx), "u32[idx + 0x50000]");
    }

    fn empty_lifted() -> LiftedProgram {
        LiftedProgram {
            variables: HashMap::new(),
            expressions: HashMap::new(),
            eliminated_pcs: HashSet::new(),
            var_at_use: HashMap::new(),
            declared_vars: HashSet::new(),
            stack_vars: HashMap::new(),
            call_targets: HashMap::new(),
            direct_call_sites: HashMap::new(),
            call_param_regs: HashMap::new(),
            var_name_to_def_pc: HashMap::new(),
            epilogue_blocks: HashMap::new(),
            suppressed_blocks: HashSet::new(),
            memory_base: None,
            heap_alloc: None,
            hidden_labels: HashSet::new(),
            linear_memory_offset: None,
            heap_alloc_data_ptr: None,
        }
    }

    #[test]
    fn test_resolve_eliminated_vars() {
        let mut lifted = empty_lifted();

        // Define var_a = 42 at PC 0 (eliminated)
        lifted.variables.insert(
            (0, 2),
            Variable {
                name: "var_a".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.expressions.insert(0, Expression::Const(42));
        lifted.var_name_to_def_pc.insert("var_a".to_string(), 0);
        lifted.eliminated_pcs.insert(0);

        // Define var_b = var_a + 10 at PC 5 (eliminated)
        lifted.variables.insert(
            (5, 3),
            Variable {
                name: "var_b".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.expressions.insert(
            5,
            Expression::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expression::Var("var_a".to_string())),
                rhs: Box::new(Expression::Const(10)),
            },
        );
        lifted.var_name_to_def_pc.insert("var_b".to_string(), 5);
        lifted.eliminated_pcs.insert(5);

        // Define var_c = var_b * 2 at PC 10 (NOT eliminated — still live)
        lifted.variables.insert(
            (10, 4),
            Variable {
                name: "var_c".to_string(),
                var_type: VarType::U64,
            },
        );
        lifted.expressions.insert(
            10,
            Expression::BinOp {
                op: BinOp::Mul,
                lhs: Box::new(Expression::Var("var_b".to_string())),
                rhs: Box::new(Expression::Const(2)),
            },
        );
        lifted.var_name_to_def_pc.insert("var_c".to_string(), 10);

        // Expression referencing eliminated var_b: should resolve to (42 + 10)
        let expr = Expression::Var("var_b".to_string());
        let resolved = lifted.resolve_eliminated_vars(&expr);
        assert_eq!(
            format_expression(&resolved, &ctx()),
            "42 + 10",
            "var_b should be resolved to its definition (42 + 10)"
        );

        // Expression referencing live var_c: should stay as var_c
        let expr2 = Expression::Var("var_c".to_string());
        let resolved2 = lifted.resolve_eliminated_vars(&expr2);
        assert_eq!(
            format_expression(&resolved2, &ctx()),
            "var_c",
            "var_c should NOT be resolved (not eliminated)"
        );

        // Compound expression: var_b + var_c should partially resolve
        let compound = Expression::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expression::Var("var_b".to_string())),
            rhs: Box::new(Expression::Var("var_c".to_string())),
        };
        let resolved3 = lifted.resolve_eliminated_vars(&compound);
        assert_eq!(
            format_expression(&resolved3, &ctx()),
            "42 + 10 + var_c",
            "Should resolve eliminated var_b but keep live var_c"
        );
    }
}
