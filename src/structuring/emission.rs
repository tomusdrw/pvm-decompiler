use super::{CondOp, Condition, Operand, StructuralAnalysis, Structure, extract_condition};
use crate::cfg::ControlFlowGraph;
use crate::instruction::InstructionShape;
use crate::lifting::LiftedProgram;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use wasm_pvm::pvm::Instruction;

use super::FunctionSignature;

impl StructuralAnalysis {
    /// Produce a summary string with structure counts.
    pub fn summarize(&self) -> String {
        let mut output = String::new();
        output.push_str("=== Structural Analysis ===\n\n");

        let loops = self
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::Loop { .. }))
            .count();
        let ifs = self
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::IfThenElse { .. }))
            .count();
        let switches = self
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::Switch { .. }))
            .count();

        let _ = writeln!(output, "Loops detected: {}", loops);
        let _ = writeln!(output, "If-then-else detected: {}", ifs);
        let _ = writeln!(output, "Switch/case detected: {}", switches);

        for s in &self.structures {
            match s {
                Structure::Loop {
                    header,
                    latch,
                    body,
                    condition,
                } => {
                    let _ = write!(
                        output,
                        "\n  Loop: header={:#06x}, latch={:#06x}, body_size={}",
                        header,
                        latch,
                        body.len()
                    );
                    if let Some(cond) = condition {
                        let _ = write!(output, ", condition={}", format_condition(cond));
                    }
                    output.push('\n');
                }
                Structure::IfThenElse {
                    header,
                    then_blocks,
                    else_blocks,
                    join,
                    condition,
                } => {
                    let kind = if else_blocks.is_empty() {
                        "if-then"
                    } else {
                        "if-then-else"
                    };
                    let _ = write!(output, "\n  {}: header={:#06x}", kind, header);
                    if !then_blocks.is_empty() {
                        let _ = write!(output, ", then=[{:#06x}]", then_blocks[0]);
                    }
                    if !else_blocks.is_empty() {
                        let _ = write!(output, ", else=[{:#06x}]", else_blocks[0]);
                    }
                    if let Some(j) = join {
                        let _ = write!(output, ", join={:#06x}", j);
                    }
                    if let Some(cond) = condition {
                        let _ = write!(output, ", condition={}", format_condition(cond));
                    }
                    output.push('\n');
                }
                Structure::Switch {
                    header, reg, cases, ..
                } => {
                    let _ = writeln!(
                        output,
                        "\n  Switch: header={:#06x}, reg=r{}, cases={}",
                        header,
                        reg,
                        cases.len()
                    );
                }
            }
        }

        output
    }

    /// Generate pseudo-code representation of the program.
    /// When `lifted` is provided, uses variable names and folded expressions.
    /// When `sig` is provided, wraps the output in a function declaration.
    pub fn pseudo_code(
        &self,
        cfg: &ControlFlowGraph,
        mut lifted: Option<&mut LiftedProgram>,
        sig: Option<&FunctionSignature>,
    ) -> String {
        let mut header_line = String::new();

        // Emit function header
        if let Some(sig) = sig {
            let params_str: Vec<String> = sig
                .params
                .iter()
                .map(|&reg| {
                    if let Some(ref lifted) = lifted {
                        // Use the variable name for this parameter if available
                        if let Some(name) = lifted.var_at_use.get(&(cfg.entry_pc, reg)) {
                            let type_str = lifted
                                .variables
                                .values()
                                .find(|v| v.name == *name)
                                .map(|v| format!("{}", v.var_type))
                                .unwrap_or_else(|| "u64".to_string());
                            return format!("{}: {}", name, type_str);
                        }
                    }
                    format!("r{}: u64", reg)
                })
                .collect();
            let _ = writeln!(header_line, "fn {}({}) {{", sig.name, params_str.join(", "));
        }

        // Build block labels for readable goto targets.
        let labels = build_block_labels(cfg, &self.structures);

        // Build lookup maps for structures
        let mut loop_map: HashMap<usize, &Structure> = HashMap::new();
        let mut if_map: HashMap<usize, &Structure> = HashMap::new();
        let mut switch_map: HashMap<usize, &Structure> = HashMap::new();

        for s in &self.structures {
            match s {
                Structure::Loop { header, .. } => {
                    loop_map.insert(*header, s);
                }
                Structure::IfThenElse { header, .. } => {
                    if_map.insert(*header, s);
                }
                Structure::Switch {
                    header,
                    is_dispatch,
                    ..
                } => {
                    if !is_dispatch {
                        switch_map.insert(*header, s);
                    }
                }
            }
        }

        // Pre-pass: detect for-loops and suppress their init/step PCs from normal emission.
        let mut for_loop_map: HashMap<usize, ForLoopInfo> = HashMap::new();
        for s in &self.structures {
            if let Structure::Loop {
                header,
                body,
                latch,
                condition,
                ..
            } = s
                && let Some(info) = detect_for_loop_pattern(
                    cfg,
                    *header,
                    *latch,
                    body,
                    condition.as_ref(),
                    lifted.as_deref(),
                )
            {
                let mut info = info;
                // Suppress the init instruction from its block's normal emission
                if let Some(ref mut lifted) = lifted {
                    lifted.eliminated_pcs.insert(info.init_pc);

                    // Coalesce init and step variable names so the loop uses
                    // a single name for the induction variable.
                    let init_name = lifted
                        .variables
                        .get(&(info.init_pc, info.cond_reg))
                        .map(|v| v.name.clone());
                    let step_name = lifted
                        .variables
                        .get(&(info.step_pc, info.cond_reg))
                        .map(|v| v.name.clone());
                    if let (Some(init_name), Some(step_name)) = (&init_name, &step_name)
                        && init_name != step_name
                    {
                        lifted.coalesce_variable(step_name, init_name);
                        // Re-format the step string with the coalesced name
                        if let Some(block) = cfg.blocks.get(&info.step_pc)
                            && let Some((_, instr)) = block
                                .instructions
                                .iter()
                                .find(|(pc, _)| *pc == info.step_pc)
                            && let Some((raw, _)) = lifted.format_pc_raw(info.step_pc, instr)
                        {
                            info.step_str = raw;
                        }
                    }
                }
                for_loop_map.insert(*header, info);
            }
        }

        // Create the emitter with all mutable state.
        let mut em = Emitter {
            cfg,
            output: if sig.is_some() {
                String::new()
            } else {
                "=== Pseudo-Code ===\n\n".to_string()
            },
            emitted: HashSet::new(),
            lifted,
            labels,
            if_map,
            loop_map,
            for_loop_map,
        };

        for &block_pc in &self.dom_tree.rpo {
            if em.emitted.contains(&block_pc) {
                continue;
            }

            // Emit label if this block has one.
            if let Some(label) = em.labels.get(&block_pc) {
                let _ = writeln!(em.output, "{}:", label);
            }

            if let Some(Structure::Loop {
                body,
                latch,
                condition,
                ..
            }) = em.loop_map.get(&block_pc)
            {
                em.emit_loop(block_pc, body, *latch, condition, 0);
            } else if let Some(Structure::IfThenElse {
                then_blocks,
                else_blocks,
                condition,
                ..
            }) = em.if_map.get(&block_pc).copied()
            {
                em.emit_if(
                    block_pc,
                    then_blocks,
                    else_blocks,
                    condition.as_ref(),
                    0,
                    None,
                );
            } else if let Some(Structure::Switch { reg, cases, .. }) = switch_map.get(&block_pc) {
                em.emit_switch(block_pc, *reg, cases);
            } else {
                // Plain block
                em.emit_block_body(block_pc, 0, false);
                em.emitted.insert(block_pc);
            }
        }

        em.emit_switch_targets();

        let output = em.output;

        // If we have a function signature, indent the body
        if sig.is_some() {
            // Split off the first line (fn header) from the rest (body)
            let lines: Vec<&str> = output.lines().collect();
            let mut result = header_line;
            for line in &lines {
                if line.is_empty() {
                    result.push('\n');
                } else {
                    let _ = writeln!(result, "    {}", line);
                }
            }
            result.push_str("}\n");
            return fix_blank_lines(&result);
        }

        fix_blank_lines(&output)
    }
}

/// Groups mutable emission state so that emission helper methods have clean signatures.
///
/// Created once inside `pseudo_code` and passed by `&mut self` to the helpers.
struct Emitter<'a> {
    cfg: &'a ControlFlowGraph,
    output: String,
    emitted: HashSet<usize>,
    lifted: Option<&'a mut LiftedProgram>,
    labels: HashMap<usize, String>,
    if_map: HashMap<usize, &'a Structure>,
    loop_map: HashMap<usize, &'a Structure>,
    for_loop_map: HashMap<usize, ForLoopInfo>,
}

impl<'a> Emitter<'a> {
    fn emit_if(
        &mut self,
        header: usize,
        then_blocks: &[usize],
        else_blocks: &[usize],
        condition: Option<&Condition>,
        indent: usize,
        loop_context: Option<(&HashSet<usize>, usize)>,
    ) {
        let prefix = "    ".repeat(indent);
        let inner_prefix = "    ".repeat(indent + 1);

        // Suppress the branch and its inlined condition variable definition.
        if let Some(cond) = condition {
            self.eliminate_condition_def(header, cond);
        }

        // Emit header block instructions (before the branch)
        self.emit_block_body(header, indent, true);

        let cond_str = condition
            .map(|c| format_condition_maybe_lifted(c, self.cfg, header, self.lifted.as_deref()))
            .unwrap_or_else(|| "...".to_string());
        let _ = writeln!(self.output, "{}if ({}) {{", prefix, cond_str);

        for &tb in then_blocks {
            let ctrl = self.emit_block_with_loop_control(tb, indent + 1, loop_context);
            if let Some(keyword) = ctrl {
                let _ = writeln!(self.output, "{}{}", inner_prefix, keyword);
                self.emitted.insert(tb);
                break; // Suppress unreachable blocks after break/continue
            }
            self.emitted.insert(tb);
        }

        if !else_blocks.is_empty() {
            // Check if all else blocks are Trap-only (renders as just `return`).
            // If so, suppress the else clause entirely.
            let all_trap_only = else_blocks.iter().all(|&eb| {
                self.cfg.blocks.get(&eb).is_some_and(|b| {
                    b.instructions.len() == 1 && matches!(b.instructions[0].1, Instruction::Trap)
                })
            });

            if all_trap_only {
                // Mark else blocks as emitted but don't output them.
                for &eb in else_blocks {
                    self.emitted.insert(eb);
                }
            } else {
                // Emit else blocks into a temporary buffer to check if any content is produced.
                let len_before = self.output.len();

                for &eb in else_blocks {
                    let ctrl = self.emit_block_with_loop_control(eb, indent + 1, loop_context);
                    if let Some(keyword) = ctrl {
                        let _ = writeln!(self.output, "{}{}", inner_prefix, keyword);
                        self.emitted.insert(eb);
                        break; // Suppress unreachable blocks after break/continue
                    }
                    self.emitted.insert(eb);
                }

                // Only emit the `else` clause if the else blocks produced content.
                let has_else_content = self.output.len() > len_before;
                if has_else_content {
                    // Insert "} else {" before the else content
                    self.output
                        .insert_str(len_before, &format!("{}}} else {{\n", prefix));
                }
            }
        }

        let _ = writeln!(self.output, "{}}}", prefix);
        self.emitted.insert(header);
    }

    /// Suppress the branch instruction and its inlined condition variable definition
    /// for a block header. The condition is shown in the if/while/for header, so the
    /// standalone definition is redundant.
    fn eliminate_condition_def(&mut self, header_pc: usize, cond: &Condition) {
        if let Some(header_block) = self.cfg.blocks.get(&header_pc)
            && let Some((branch_pc, _)) = header_block.instructions.last()
            && let Some(ref mut lifted) = self.lifted
        {
            lifted.eliminated_pcs.insert(*branch_pc);

            if let Operand::Reg(reg) = &cond.lhs
                && let Operand::Imm(0) = &cond.rhs
                && matches!(cond.op, CondOp::Ne | CondOp::Eq)
                && let Some(var_name) = lifted.var_at_use.get(&(*branch_pc, *reg)).cloned()
                && let Some(def_pc) = lifted.var_name_to_def_pc.get(&var_name).copied()
            {
                lifted.eliminated_pcs.insert(def_pc);
            }
        }
    }

    /// Check if a block would emit break or continue when inside a loop.
    /// Returns true if the block exits the loop or jumps back to the header.
    fn is_loop_terminal_block(
        cfg: &ControlFlowGraph,
        block_pc: usize,
        body: &HashSet<usize>,
        header_pc: usize,
    ) -> bool {
        if let Some(block) = cfg.blocks.get(&block_pc) {
            let exits_loop = block
                .successors
                .iter()
                .any(|s| !body.contains(s) && *s != header_pc);
            let continues_loop = block.successors.len() == 1 && block.successors[0] == header_pc;
            let is_trap = block
                .instructions
                .last()
                .is_some_and(|(_, instr)| matches!(instr, Instruction::Trap));
            !is_trap && (exits_loop || continues_loop)
        } else {
            false
        }
    }

    /// Compute a topological ordering of body blocks using reverse post-order DFS.
    /// This ensures blocks are emitted in control-flow order rather than PC order,
    /// preventing issues like the latch block (with `continue`) appearing before
    /// inner loop blocks that have higher PCs.
    fn compute_body_order(&self, body: &HashSet<usize>, header_pc: usize) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();

        // DFS from header's successors within the body
        if let Some(header_block) = self.cfg.blocks.get(&header_pc) {
            // Sort successors by PC for deterministic tie-breaking
            let mut succs: Vec<usize> = header_block
                .successors
                .iter()
                .copied()
                .filter(|s| body.contains(s) && *s != header_pc)
                .collect();
            succs.sort();

            for succ in succs {
                self.dfs_body_order(succ, body, header_pc, &mut visited, &mut post_order);
            }
        }

        // Reverse post-order gives topological order
        post_order.reverse();
        post_order
    }

    fn dfs_body_order(
        &self,
        pc: usize,
        body: &HashSet<usize>,
        header_pc: usize,
        visited: &mut HashSet<usize>,
        post_order: &mut Vec<usize>,
    ) {
        if !visited.insert(pc) {
            return;
        }

        // Follow successors within the body (skip header = back-edge)
        if let Some(block) = self.cfg.blocks.get(&pc) {
            let mut succs: Vec<usize> = block
                .successors
                .iter()
                .copied()
                .filter(|s| body.contains(s) && *s != header_pc)
                .collect();
            succs.sort();

            for succ in succs {
                self.dfs_body_order(succ, body, header_pc, visited, post_order);
            }
        }

        // Also follow if-then-else branches (they may not be in block.successors)
        if let Some(Structure::IfThenElse {
            then_blocks,
            else_blocks,
            ..
        }) = self.if_map.get(&pc)
        {
            let mut branches: Vec<usize> = then_blocks
                .iter()
                .chain(else_blocks.iter())
                .copied()
                .filter(|b| body.contains(b) && *b != header_pc)
                .collect();
            branches.sort();

            for b in branches {
                self.dfs_body_order(b, body, header_pc, visited, post_order);
            }
        }

        post_order.push(pc);
    }

    /// Compute which blocks in a loop body are reachable from the header
    /// through non-terminal paths (i.e., not through break/continue blocks).
    /// A block that would emit break or continue is itself reachable, but
    /// its successors (within the loop body) are not traversed further.
    fn compute_reachable_in_loop(&self, body: &HashSet<usize>, header_pc: usize) -> HashSet<usize> {
        let mut reachable = HashSet::new();
        let mut worklist = VecDeque::new();

        // Start from the header's successors within the body
        if let Some(header_block) = self.cfg.blocks.get(&header_pc) {
            for &succ in &header_block.successors {
                if body.contains(&succ) && succ != header_pc {
                    worklist.push_back(succ);
                }
            }
        }

        while let Some(pc) = worklist.pop_front() {
            if !reachable.insert(pc) {
                continue;
            }

            let is_terminal = Self::is_loop_terminal_block(self.cfg, pc, body, header_pc);

            // If this block is an if-then-else header, check if ALL branches terminate
            let if_terminates = if let Some(Structure::IfThenElse {
                then_blocks,
                else_blocks,
                ..
            }) = self.if_map.get(&pc)
            {
                let all_then_terminal = then_blocks
                    .iter()
                    .all(|&tb| Self::is_loop_terminal_block(self.cfg, tb, body, header_pc));
                let all_else_terminal = else_blocks
                    .iter()
                    .all(|&eb| Self::is_loop_terminal_block(self.cfg, eb, body, header_pc));
                !then_blocks.is_empty()
                    && !else_blocks.is_empty()
                    && all_then_terminal
                    && all_else_terminal
            } else {
                false
            };

            // Don't traverse past terminal blocks or if-then-else where all branches terminate
            if is_terminal || if_terminates {
                continue;
            }

            // Follow successors within the loop body
            if let Some(block) = self.cfg.blocks.get(&pc) {
                for &succ in &block.successors {
                    if body.contains(&succ) && succ != header_pc {
                        worklist.push_back(succ);
                    }
                }
            }

            // Also follow if-then-else branches
            if let Some(Structure::IfThenElse {
                then_blocks,
                else_blocks,
                ..
            }) = self.if_map.get(&pc)
            {
                for &tb in then_blocks {
                    if body.contains(&tb) {
                        worklist.push_back(tb);
                    }
                }
                for &eb in else_blocks {
                    if body.contains(&eb) {
                        worklist.push_back(eb);
                    }
                }
            }
        }

        reachable
    }

    /// Emit a block body, detecting break/continue when inside a loop.
    /// Returns `Some("break")` or `Some("continue")` if the block exits/continues the loop.
    fn emit_block_with_loop_control(
        &mut self,
        block_pc: usize,
        indent: usize,
        loop_context: Option<(&HashSet<usize>, usize)>,
    ) -> Option<&'static str> {
        if let Some((loop_body, loop_header)) = loop_context
            && let Some(block) = self.cfg.blocks.get(&block_pc)
        {
            let exits_loop = block
                .successors
                .iter()
                .any(|s| !loop_body.contains(s) && *s != loop_header);
            let continues_loop = block.successors.len() == 1 && block.successors[0] == loop_header;
            let is_trap = block
                .instructions
                .last()
                .is_some_and(|(_, instr)| matches!(instr, Instruction::Trap));

            if !is_trap && (exits_loop || continues_loop) {
                self.emit_block_body(block_pc, indent, true);
                if exits_loop {
                    return Some("break");
                } else {
                    return Some("continue");
                }
            }
        }
        self.emit_block_body(block_pc, indent, false);
        None
    }

    /// Emit the instructions in a block as pseudo-code lines.
    /// If `skip_terminator` is true, the last instruction (branch/jump) is not emitted.
    /// When `lifted` is provided, uses variable names and skips eliminated PCs.
    fn emit_block_body(&mut self, block_pc: usize, indent: usize, skip_terminator: bool) {
        let prefix = "    ".repeat(indent);
        let len_before = self.output.len();
        if let Some(block) = self.cfg.blocks.get(&block_pc) {
            let len = block.instructions.len();
            let end = if skip_terminator && len > 0 {
                len - 1
            } else {
                len
            };

            for (pc, instr) in &block.instructions[..end] {
                if let Some(ref mut lifted) = self.lifted {
                    // Skip eliminated PCs (folded/propagated).
                    if lifted.eliminated_pcs.contains(pc) {
                        continue;
                    }
                    // Check if this Jump is a function call
                    if let Instruction::Jump { offset } = instr {
                        let target =
                            crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                        if let Some(callee) = lifted.call_targets.get(&target) {
                            let _ = writeln!(self.output, "{}{}()", prefix, callee);
                            continue;
                        }
                    }
                    // Check if this JumpInd targets a known function entry
                    if let Instruction::JumpInd { reg, .. } = instr {
                        // First try: resolve register to a constant PC in call_targets
                        if let Some(callee) = lifted.resolve_indirect_call(*pc, *reg) {
                            let _ = writeln!(self.output, "{}{}()", prefix, callee);
                            continue;
                        }
                        // Second try: check if this block is a known indirect call site
                        if let Some(callee) = lifted.indirect_call_targets.get(&block_pc).cloned() {
                            let _ = writeln!(self.output, "{}{}()", prefix, callee);
                            continue;
                        }
                        // Suppress remaining JumpInd in lifted mode — they're dispatch
                        // infrastructure or already represented as function calls above.
                        continue;
                    }
                    // Skip noise instructions in lifted mode.
                    if matches!(instr, Instruction::Fallthrough | Instruction::Jump { .. }) {
                        continue;
                    }
                    // Render conditional branches with goto labels instead of raw offsets.
                    let shape = InstructionShape::classify(instr);
                    if shape.is_conditional_branch()
                        && let Some(offset) = shape.branch_offset()
                    {
                        let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, offset);
                        let target_label = self
                            .labels
                            .get(&target)
                            .cloned()
                            .unwrap_or_else(|| format!("block_{:04x}", target));
                        let cond_str = if let Some(cond) = extract_condition(instr) {
                            format_condition_maybe_lifted(&cond, self.cfg, block_pc, Some(lifted))
                        } else {
                            "...".to_string()
                        };
                        let _ = writeln!(
                            self.output,
                            "{}if ({}) goto {};",
                            prefix, cond_str, target_label
                        );
                        continue;
                    }
                    if let Some(line) = lifted.format_pc(*pc, instr) {
                        let _ = writeln!(self.output, "{}{}", prefix, line);
                    }
                } else {
                    let _ = writeln!(
                        self.output,
                        "{}{:#06x}: {}",
                        prefix,
                        pc,
                        format_instruction(instr)
                    );
                }
            }
        }
        // Emit return/halt for epilogue blocks (after all other instructions).
        if let Some(ref lifted) = self.lifted
            && let Some(kind) = lifted.epilogue_blocks.get(&block_pc)
        {
            match kind {
                crate::functions::EpilogueKind::Return { .. } => {
                    let _ = writeln!(self.output, "{}return", prefix);
                }
                crate::functions::EpilogueKind::Halt { .. } => {
                    let _ = writeln!(self.output, "{}halt()", prefix);
                }
            }
        }

        // Blank line between basic blocks when content was emitted.
        if self.output.len() > len_before {
            self.output.push('\n');
        }
    }

    /// Emit a loop structure (while or for).
    fn emit_loop(
        &mut self,
        header_pc: usize,
        body: &HashSet<usize>,
        latch: usize,
        condition: &Option<Condition>,
        indent: usize,
    ) {
        let prefix = "    ".repeat(indent);
        let cond_str = condition
            .as_ref()
            .map(|c| format_condition_maybe_lifted(c, self.cfg, header_pc, self.lifted.as_deref()))
            .unwrap_or_else(|| "...".to_string());

        // Clone for-loop info to avoid holding a borrow of self.for_loop_map
        // across mutable self calls.
        let for_loop_info = self.for_loop_map.get(&header_pc).cloned();

        if let Some(ref info) = for_loop_info {
            let _ = writeln!(
                self.output,
                "{}for ({}; {}; {}) {{",
                prefix, info.init_str, cond_str, info.step_str
            );
        } else {
            let _ = writeln!(self.output, "{}while ({}) {{", prefix, cond_str);
        }

        // Suppress the branch and its inlined condition variable definition.
        if let Some(cond) = condition.as_ref() {
            self.eliminate_condition_def(header_pc, cond);
        }

        // Emit header block body (before the condition branch)
        self.emit_block_body(header_pc, indent + 1, true);

        // Compute topological ordering (RPO) of body blocks for control-flow-order emission.
        // This prevents the latch block (with `continue`) from appearing before inner loop blocks.
        let body_ordered = self.compute_body_order(body, header_pc);

        // Pre-compute which blocks are reachable from the header through the loop body,
        // stopping traversal at blocks that would emit break or continue (terminal blocks).
        // Blocks not reachable this way are unreachable after break/continue and should be suppressed.
        let reachable = self.compute_reachable_in_loop(body, header_pc);

        // Pre-compute which blocks will actually be emitted, to detect the last one.
        let emittable: Vec<usize> = body_ordered
            .iter()
            .copied()
            .filter(|&pc| pc != header_pc && reachable.contains(&pc))
            .collect();
        let last_emittable = emittable.last().copied();

        for &body_pc in &body_ordered {
            if body_pc == header_pc || self.emitted.contains(&body_pc) {
                continue;
            }

            // Skip blocks that are unreachable from the header through non-terminal paths.
            if !reachable.contains(&body_pc) {
                self.emitted.insert(body_pc);
                continue;
            }

            let is_latch = body_pc == latch && for_loop_info.is_some();
            // Suppress step instruction in latch block for for-loops
            if is_latch
                && let Some(ref info) = for_loop_info
                && let Some(ref mut lifted) = self.lifted
            {
                lifted.eliminated_pcs.insert(info.step_pc);
            }

            // Check if this body block is a nested loop header
            if let Some(Structure::Loop {
                body: inner_body,
                latch: inner_latch,
                condition: inner_condition,
                ..
            }) = self.loop_map.get(&body_pc)
            {
                self.emit_loop(
                    body_pc,
                    inner_body,
                    *inner_latch,
                    inner_condition,
                    indent + 1,
                );
                continue;
            }

            // Check if this body block is an if-then-else
            if let Some(Structure::IfThenElse {
                then_blocks,
                else_blocks,
                condition,
                ..
            }) = self.if_map.get(&body_pc).copied()
            {
                self.emit_if(
                    body_pc,
                    then_blocks,
                    else_blocks,
                    condition.as_ref(),
                    indent + 1,
                    Some((body, header_pc)),
                );
                continue;
            }

            let inner_prefix = "    ".repeat(indent + 1);
            if is_latch {
                self.emit_block_body(body_pc, indent + 1, true);
            } else {
                let ctrl =
                    self.emit_block_with_loop_control(body_pc, indent + 1, Some((body, header_pc)));
                if let Some(keyword) = ctrl {
                    // Suppress `continue` at the very end of the loop body — it's implicit.
                    let is_last = last_emittable == Some(body_pc);
                    if !(keyword == "continue" && is_last) {
                        let _ = writeln!(self.output, "{}{}", inner_prefix, keyword);
                    }
                }
            }
            self.emitted.insert(body_pc);
        }

        let _ = writeln!(self.output, "{}}}", prefix);
        self.emitted.extend(body.iter());
    }

    /// Emit a switch/case structure.
    fn emit_switch(&mut self, block_pc: usize, reg: u8, cases: &[(Vec<u32>, usize)]) {
        self.emit_block_body(block_pc, 0, true);

        let switch_var = if let Some(ref mut lifted) = self.lifted {
            if let Some(branch_pc) = last_instruction_pc(self.cfg, block_pc) {
                if let Some(name) = lifted.var_at_use.get(&(branch_pc, reg)).cloned() {
                    // Only emit a forward declaration if the variable has a definition
                    // PC within the current function's CFG (not an orphaned global ref).
                    let has_local_def =
                        lifted.var_name_to_def_pc.get(&name).is_some_and(|def_pc| {
                            self.cfg
                                .blocks
                                .values()
                                .any(|b| b.instructions.iter().any(|(pc, _)| pc == def_pc))
                        });
                    if has_local_def && lifted.declared_vars.insert(name.clone()) {
                        let type_str = lifted
                            .variables
                            .values()
                            .find(|v| v.name == name)
                            .map(|v| format!("{}", v.var_type))
                            .unwrap_or_else(|| "u64".to_string());
                        let _ = writeln!(self.output, "let {}: {};", name, type_str);
                    }
                    name
                } else {
                    format!("r{}", reg)
                }
            } else {
                format!("r{}", reg)
            }
        } else {
            format!("r{}", reg)
        };
        let _ = writeln!(self.output, "switch ({}) {{", switch_var);
        for (values, target) in cases.iter() {
            let vals: Vec<String> = values.iter().map(|v| format!("{}", v)).collect();
            let target_label = format_goto_target(*target, &self.labels);
            let _ = writeln!(
                self.output,
                "    case {}: goto {};",
                vals.join(", "),
                target_label
            );
        }
        self.output.push_str("}\n");
        self.emitted.insert(block_pc);
    }

    /// Emit switch target blocks that weren't reached by the RPO walk.
    fn emit_switch_targets(&mut self) {
        let mut switch_targets: Vec<usize> = self
            .labels
            .keys()
            .copied()
            .filter(|pc| !self.emitted.contains(pc) && self.cfg.blocks.contains_key(pc))
            .collect();
        switch_targets.sort();

        for target_pc in switch_targets {
            if self.emitted.contains(&target_pc) {
                continue;
            }
            let _ = writeln!(self.output, "{}:", self.labels[&target_pc]);

            // BFS forward walk to collect reachable blocks
            let mut reachable = Vec::new();
            let mut visited: HashSet<usize> = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(target_pc);
            while let Some(pc) = queue.pop_front() {
                if !visited.insert(pc) || self.emitted.contains(&pc) {
                    continue;
                }
                reachable.push(pc);
                self.emitted.insert(pc);
                if let Some(block) = self.cfg.blocks.get(&pc) {
                    for &succ in &block.successors {
                        if !visited.contains(&succ) && !self.emitted.contains(&succ) {
                            queue.push_back(succ);
                        }
                    }
                }
            }

            for &block_pc in &reachable {
                if block_pc != target_pc
                    && let Some(label) = self.labels.get(&block_pc)
                {
                    let _ = writeln!(self.output, "{}:", label);
                }

                if let Some(Structure::IfThenElse {
                    then_blocks,
                    else_blocks,
                    condition,
                    ..
                }) = self.if_map.get(&block_pc).copied()
                {
                    self.emit_if(
                        block_pc,
                        then_blocks,
                        else_blocks,
                        condition.as_ref(),
                        0,
                        None,
                    );
                } else {
                    self.emit_block_body(block_pc, 0, false);
                }
            }
        }
    }
}

/// Post-process pseudo-code output to fix blank line placement:
/// - Remove blank lines immediately before lines starting with `}` or `} else {`
/// - Add a blank line after `}` lines (except when followed by another `}` or `} else {`)
fn fix_blank_lines(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut result = Vec::new();

    // First pass: collect lines, removing blank lines before closing braces.
    for (i, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Skip blank lines that appear immediately before a closing brace line.
        if trimmed.is_empty() {
            // Look ahead to find the next non-blank line.
            let next_non_blank = lines[i + 1..]
                .iter()
                .find(|l| !l.trim().is_empty())
                .map(|l| l.trim());
            if let Some(next) = next_non_blank
                && next.starts_with('}')
            {
                continue; // Skip this blank line
            }
        }
        result.push(line);
    }

    // Second pass: ensure a blank line after `}` lines, except when
    // the next line is also a `}`, `} else {`, or end of output.
    let mut final_lines: Vec<&str> = Vec::new();
    for (i, &line) in result.iter().enumerate() {
        final_lines.push(line);
        let trimmed = line.trim();
        if trimmed == "}" || trimmed == "};" {
            // Check if next line exists and isn't blank or another closing brace.
            if let Some(&next) = result.get(i + 1) {
                let next_trimmed = next.trim();
                if !next_trimmed.is_empty()
                    && !next_trimmed.starts_with('}')
                    && next_trimmed != "} else {"
                {
                    final_lines.push("");
                }
            }
        }
    }

    // Third pass: suppress consecutive duplicate `return` statements.
    let mut deduped: Vec<&str> = Vec::new();
    let mut prev_was_return = false;
    for &line in &final_lines {
        let trimmed = line.trim();
        if trimmed == "return" {
            if prev_was_return {
                continue; // Skip duplicate return
            }
            prev_was_return = true;
        } else if !trimmed.is_empty() {
            prev_was_return = false;
        }
        // Keep blank lines between non-return content
        deduped.push(line);
    }

    let mut out = deduped.join("\n");
    out.push('\n');
    out
}

/// Build human-readable labels for blocks that are targets of goto/switch statements.
/// Information about a detected for-loop pattern.
#[derive(Clone)]
struct ForLoopInfo {
    /// The initialization expression (e.g. "let var_0 = 0")
    init_str: String,
    /// The step expression (e.g. "var_0 = var_0 + 1")
    step_str: String,
    /// PC of the init instruction (to suppress from normal block emission)
    init_pc: usize,
    /// PC of the step instruction (to suppress from latch block emission)
    step_pc: usize,
    /// The condition register (induction variable register)
    cond_reg: u8,
}

/// Try to detect a for-loop pattern from a while loop.
///
/// A for-loop has: init before the loop, condition in the header, step in the latch.
/// Returns `Some(ForLoopInfo)` if the pattern matches.
fn detect_for_loop_pattern(
    cfg: &ControlFlowGraph,
    header_pc: usize,
    latch_pc: usize,
    body: &HashSet<usize>,
    condition: Option<&Condition>,
    lifted: Option<&LiftedProgram>,
) -> Option<ForLoopInfo> {
    use crate::instruction::InstructionShape;

    let lifted = lifted?;
    let condition = condition?;

    // Get the condition register (LHS of the branch condition)
    let cond_reg = match &condition.lhs {
        Operand::Reg(reg) => *reg,
        _ => return None,
    };

    // Find the init: look at predecessors of the header that are NOT in the loop body.
    let header_block = cfg.blocks.get(&header_pc)?;
    let init_preds: Vec<usize> = header_block
        .predecessors
        .iter()
        .filter(|p| !body.contains(p))
        .copied()
        .collect();

    // Exactly one non-loop predecessor
    if init_preds.len() != 1 {
        return None;
    }
    let init_block_pc = init_preds[0];

    // Find the last instruction in the init block that defines cond_reg.
    // We deliberately check even eliminated PCs, since the init may have been
    // constant-propagated away but we still want it in the for-header.
    // Scan backwards through all instructions (not just the last one) because
    // the init assignment might be followed by other setup instructions
    // (e.g., initializing a step constant for Sub32-based counting).
    let init_block = cfg.blocks.get(&init_block_pc)?;
    let mut init_result = None;
    for (pc, instr) in init_block.instructions.iter().rev() {
        if matches!(instr, Instruction::Fallthrough | Instruction::Jump { .. }) {
            continue;
        }
        // Check if this instruction defines the condition register
        let shape = InstructionShape::classify(instr);
        if shape.def_reg() == Some(cond_reg) {
            let (raw, declare_var) = lifted.format_pc_raw(*pc, instr)?;
            let prefix = match declare_var {
                Some(ref dv) if !lifted.declared_vars.contains(dv) => "let ",
                _ => "",
            };
            init_result = Some((format!("{}{}", prefix, raw), *pc));
            break;
        }
    }

    let (init_str, init_pc) = init_result?;

    // Find the step: scan backwards through the latch block for a non-eliminated
    // instruction that defines cond_reg (e.g., i = i + 1 or i = i - 1).
    // Scan all instructions (not just the last one) to handle cases where
    // the step is followed by other instructions in the latch block.
    let latch_block = cfg.blocks.get(&latch_pc)?;
    let mut step_result = None;
    for (pc, instr) in latch_block.instructions.iter().rev() {
        if lifted.eliminated_pcs.contains(pc) {
            continue;
        }
        if matches!(instr, Instruction::Fallthrough | Instruction::Jump { .. }) {
            continue;
        }
        let shape = InstructionShape::classify(instr);
        if shape.def_reg() == Some(cond_reg) {
            let (raw, _) = lifted.format_pc_raw(*pc, instr)?;
            step_result = Some((raw, *pc));
            break;
        }
    }

    let (step_str, step_pc) = step_result?;

    Some(ForLoopInfo {
        init_str,
        step_str,
        init_pc,
        step_pc,
        cond_reg,
    })
}

fn build_block_labels(_cfg: &ControlFlowGraph, structures: &[Structure]) -> HashMap<usize, String> {
    let mut labels = HashMap::new();

    // Collect all goto targets: switch case targets and blocks not covered by structures.
    let mut goto_targets: HashSet<usize> = HashSet::new();

    for s in structures {
        if let Structure::Switch {
            cases,
            is_dispatch: false,
            ..
        } = s
        {
            for (_, target) in cases {
                goto_targets.insert(*target);
            }
        }
    }

    // Assign labels only to actual goto/switch targets.
    let mut sorted_targets: Vec<usize> = goto_targets.into_iter().collect();
    sorted_targets.sort();

    for &pc in &sorted_targets {
        labels.insert(pc, format!("block_{:04x}", pc));
    }

    labels
}

/// Format a goto target using a label if available, otherwise as a hex address.
fn format_goto_target(target: usize, labels: &HashMap<usize, String>) -> String {
    labels
        .get(&target)
        .cloned()
        .unwrap_or_else(|| format!("{:#06x}", target))
}

/// Get the PC of the last instruction in a block (the branch/terminator).
fn last_instruction_pc(cfg: &ControlFlowGraph, block_pc: usize) -> Option<usize> {
    cfg.blocks
        .get(&block_pc)
        .and_then(|b| b.instructions.last())
        .map(|(pc, _)| *pc)
}

/// Format a condition, using lifted variable names when a lifted program is provided.
fn format_condition_maybe_lifted(
    cond: &Condition,
    cfg: &ControlFlowGraph,
    header_pc: usize,
    lifted: Option<&LiftedProgram>,
) -> String {
    if let Some(lifted) = lifted
        && let Some(branch_pc) = last_instruction_pc(cfg, header_pc)
    {
        return format_condition_lifted(cond, branch_pc, lifted);
    }
    format_condition(cond)
}

/// Format a condition as a human-readable string.
fn format_condition(cond: &Condition) -> String {
    let lhs = format_operand(&cond.lhs);
    let rhs = format_operand(&cond.rhs);
    let op = match cond.op {
        CondOp::Eq => "==",
        CondOp::Ne => "!=",
        CondOp::GeS => ">=s",
        CondOp::GeU => ">=u",
        CondOp::LtU => "<u",
    };
    format!("{} {} {}", lhs, op, rhs)
}

/// Format a condition using lifted variable names when available.
/// When the condition is `cond_var != 0` and cond_var was defined by a comparison
/// expression (e.g. `x <u y`), inline the comparison directly.
fn format_condition_lifted(cond: &Condition, branch_pc: usize, lifted: &LiftedProgram) -> String {
    use crate::lifting::format_expression;

    // Try to inline boolean variable definitions into conditions.
    // Pattern: `cond_var != 0` where cond_var = (x <u y) → inline as `x <u y`
    // Pattern: `cond_var == 0` where cond_var = (x <u y) → inline as `!(x <u y)`
    if let Operand::Reg(reg) = &cond.lhs
        && let Operand::Imm(0) = &cond.rhs
        && matches!(cond.op, CondOp::Ne | CondOp::Eq)
        && let Some(name) = lifted.var_at_use.get(&(branch_pc, *reg))
        && let Some(expr) = lifted.expression_for_var(name)
    {
        // Check if the expression is already boolean (comparison, negation,
        // or bitwise AND/OR of booleans). If so, inline it directly.
        if crate::lifting::is_boolean_expr(expr) {
            if cond.op == CondOp::Eq {
                // Invert: `cond_var == 0` where cond_var is boolean → negate
                use crate::lifting::simplify_expression;
                let negated = crate::lifting::Expression::UnaryOp {
                    op: crate::instruction::UnaryOp::Not,
                    operand: Box::new(expr.clone()),
                };
                return format_expression(&simplify_expression(negated));
            } else {
                return format_expression(expr);
            }
        }
    }

    let lhs = format_operand_lifted(&cond.lhs, branch_pc, lifted);
    let rhs = format_operand_lifted(&cond.rhs, branch_pc, lifted);
    let op = match cond.op {
        CondOp::Eq => "==",
        CondOp::Ne => "!=",
        CondOp::GeS => ">=s",
        CondOp::GeU => ">=u",
        CondOp::LtU => "<u",
    };
    format!("{} {} {}", lhs, op, rhs)
}

fn format_operand(op: &Operand) -> String {
    match op {
        Operand::Reg(r) => format!("r{}", r),
        Operand::Imm(v) => format!("{}", v),
    }
}

fn format_operand_lifted(op: &Operand, branch_pc: usize, lifted: &LiftedProgram) -> String {
    match op {
        Operand::Reg(r) => lifted
            .var_at_use
            .get(&(branch_pc, *r))
            .cloned()
            .unwrap_or_else(|| format!("r{}", r)),
        Operand::Imm(v) => format!("{}", v),
    }
}

/// Format a single instruction as pseudo-code.
fn format_instruction(instr: &Instruction) -> String {
    InstructionShape::classify(instr).format_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_test_cfg;
    use crate::decoder::DecodedProgram;

    fn empty_program() -> DecodedProgram {
        DecodedProgram {
            jump_table: vec![],
            instructions: vec![],
            memory_base: None,
            code_len: 0,
        }
    }

    // --- Pseudo-code output tests ---

    #[test]
    fn test_pseudo_code_simple_loop() {
        // 0 -> 10 -> 20 -> 10 (back-edge), 10 -> 30
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
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 3,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![20, 30],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::Add32 {
                                dst: 2,
                                src1: 0,
                                src2: 1,
                            },
                        ),
                        (24, Instruction::Jump { offset: -14 }),
                    ],
                    vec![10],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, None, None);

        assert!(
            pseudo.contains("while"),
            "Should contain 'while': {}",
            pseudo
        );
        assert!(
            pseudo.contains("r3 != 0"),
            "Should contain condition: {}",
            pseudo
        );
        assert!(
            pseudo.contains("r0 = 42"),
            "Should contain init: {}",
            pseudo
        );
    }

    #[test]
    fn test_pseudo_code_if_else() {
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 42 }),
                        (
                            4,
                            Instruction::BranchNeImm {
                                reg: 1,
                                value: 5,
                                offset: 10,
                            },
                        ),
                    ],
                    vec![10, 20],
                ),
                (
                    10,
                    vec![(10, Instruction::LoadImm { reg: 4, value: 99 })],
                    vec![30],
                ),
                (
                    20,
                    vec![(20, Instruction::LoadImm { reg: 4, value: 0 })],
                    vec![30],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, None, None);

        assert!(pseudo.contains("if"), "Should contain 'if': {}", pseudo);
        assert!(
            pseudo.contains("r1 != 5"),
            "Should contain condition: {}",
            pseudo
        );
    }

    #[test]
    fn test_pseudo_code_lifted_conditions() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // r0 = 42, branch on r0 != 5 → if-else
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 42 }),
                        (
                            4,
                            Instruction::BranchNeImm {
                                reg: 0,
                                value: 5,
                                offset: 10,
                            },
                        ),
                    ],
                    vec![10, 20],
                ),
                (
                    10,
                    vec![(10, Instruction::LoadImm { reg: 4, value: 99 })],
                    vec![30],
                ),
                (
                    20,
                    vec![(20, Instruction::LoadImm { reg: 4, value: 0 })],
                    vec![30],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        // The condition should use the lifted variable name, not raw register
        assert!(
            !pseudo.contains("r0 != 5"),
            "Should NOT contain raw register in condition: {}",
            pseudo
        );
        assert!(
            pseudo.contains("var_0 != 5") || pseudo.contains("42 != 5"),
            "Should contain lifted variable or constant in condition: {}",
            pseudo
        );
    }

    #[test]
    fn test_lifted_condition_inlines_comparison() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // r2 = r0 <u r1 (SetLtU), then branch on r2 != 0 → should inline to "r0 <u r1"
        let cfg = build_test_cfg(
            0,
            vec![
                (
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
                        (
                            4,
                            Instruction::BranchNeImm {
                                reg: 2,
                                value: 0,
                                offset: 10,
                            },
                        ),
                    ],
                    vec![10, 20],
                ),
                (
                    10,
                    vec![(10, Instruction::LoadImm { reg: 4, value: 99 })],
                    vec![30],
                ),
                (
                    20,
                    vec![(20, Instruction::LoadImm { reg: 4, value: 0 })],
                    vec![30],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        // Should inline the comparison, not show "cond_0 != 0"
        assert!(
            !pseudo.contains("!= 0"),
            "Should NOT contain 'cond != 0', should inline comparison: {}",
            pseudo
        );
        assert!(
            pseudo.contains("<u"),
            "Should contain inlined comparison operator: {}",
            pseudo
        );
    }

    #[test]
    fn test_for_loop_detection() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // For-loop pattern:
        // block 0: r0 = 0 (init), fallthrough to header
        // block 10 (header): branch r0 != 10 → body (20) | exit (40)
        // block 20 (body): r1 = r1 + r0 (work), fallthrough to latch
        // block 30 (latch): r0 = r0 + 1 (step), jump to header
        // block 40: trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 0 }),
                        (4, Instruction::Fallthrough),
                    ],
                    vec![10],
                ),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 10,
                            offset: 10,
                        },
                    )],
                    vec![20, 40],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::Add32 {
                                dst: 1,
                                src1: 1,
                                src2: 0,
                            },
                        ),
                        (24, Instruction::Fallthrough),
                    ],
                    vec![30],
                ),
                (
                    30,
                    vec![
                        (
                            30,
                            Instruction::AddImm32 {
                                dst: 0,
                                src: 0,
                                value: 1,
                            },
                        ),
                        (34, Instruction::Jump { offset: -24 }),
                    ],
                    vec![10],
                ),
                (40, vec![(40, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        assert!(
            pseudo.contains("for ("),
            "Should contain 'for (' for detected for-loop: {}",
            pseudo
        );
        assert!(
            !pseudo.contains("while"),
            "Should NOT contain 'while' when for-loop detected: {}",
            pseudo
        );
        // Check the for-header contains init and condition.
        // With deterministic var_at_use (smallest def PC wins), the init
        // variable (var_0 at PC 0) should be used consistently.
        assert!(
            pseudo.contains("var_0 = 0"),
            "For-header should contain init 'var_0 = 0': {}",
            pseudo
        );
        assert!(
            pseudo.contains("var_0 != 10"),
            "For-header should contain condition 'var_0 != 10': {}",
            pseudo
        );
        // After coalescing, the step should also use var_0 (not var_2 or similar)
        assert!(
            pseudo.contains("var_0 = var_0 + 1"),
            "For-header step should use coalesced name 'var_0 = var_0 + 1': {}",
            pseudo
        );
    }

    #[test]
    fn test_while_loop_not_detected_as_for() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // While-loop pattern (no clear init or step for condition variable):
        // block 0: r1 = 42 (unrelated init), fallthrough to header
        // block 10 (header): branch r0 != 0 → body (20) | exit (30)
        // block 20 (body): r1 = r1 + 1, jump to header
        // block 30: trap
        //
        // r0 is the condition variable, but block 0 doesn't define r0,
        // and the latch (block 20) doesn't define r0 either.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 1, value: 42 }),
                        (4, Instruction::Fallthrough),
                    ],
                    vec![10],
                ),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![20, 30],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::AddImm32 {
                                dst: 1,
                                src: 1,
                                value: 1,
                            },
                        ),
                        (24, Instruction::Jump { offset: -14 }),
                    ],
                    vec![10],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        assert!(
            pseudo.contains("while"),
            "Should remain a while-loop when no for-pattern found: {}",
            pseudo
        );
        assert!(
            !pseudo.contains("for ("),
            "Should NOT contain 'for (' without init/step pattern: {}",
            pseudo
        );
    }

    #[test]
    fn test_counting_down_for_loop_detection() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Counting-down for-loop pattern:
        // block 0: r0 = 10 (init), fallthrough to header
        // block 10 (header): branch r0 != 0 → body (20) | exit (40)
        // block 20 (body): r1 = r1 + r0 (work), fallthrough to latch
        // block 30 (latch): r0 = r0 + (-1) (step = decrement), jump to header
        // block 40: trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 10 }),
                        (4, Instruction::Fallthrough),
                    ],
                    vec![10],
                ),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![20, 40],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::Add32 {
                                dst: 1,
                                src1: 1,
                                src2: 0,
                            },
                        ),
                        (24, Instruction::Fallthrough),
                    ],
                    vec![30],
                ),
                (
                    30,
                    vec![
                        (
                            30,
                            Instruction::AddImm32 {
                                dst: 0,
                                src: 0,
                                value: -1,
                            },
                        ),
                        (34, Instruction::Jump { offset: -24 }),
                    ],
                    vec![10],
                ),
                (40, vec![(40, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        assert!(
            pseudo.contains("for ("),
            "Counting-down loop should be detected as for-loop: {}",
            pseudo
        );
        assert!(
            !pseudo.contains("while"),
            "Should NOT contain 'while' when counting-down for-loop detected: {}",
            pseudo
        );
        // Init should set to 10
        assert!(
            pseudo.contains("var_0 = 10"),
            "For-header should contain init 'var_0 = 10': {}",
            pseudo
        );
        // Condition should be != 0
        assert!(
            pseudo.contains("var_0 != 0"),
            "For-header should contain condition 'var_0 != 0': {}",
            pseudo
        );
        // Step should show decrement: var_0 = var_0 - 1
        assert!(
            pseudo.contains("var_0 = var_0 - 1"),
            "For-header step should show decrement 'var_0 = var_0 - 1': {}",
            pseudo
        );
    }

    #[test]
    fn test_counting_down_for_loop_with_sub32() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Counting-down for-loop using Sub32 (register subtraction):
        // block 0: r0 = 10 (init), r2 = 1 (step constant), fallthrough to header
        // block 10 (header): branch r0 != 0 → body (20) | exit (40)
        // block 20 (body): r1 = r1 + 1 (work), fallthrough to latch
        // block 30 (latch): r0 = r0 - r2 (step), jump to header
        // block 40: trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 10 }),
                        (4, Instruction::LoadImm { reg: 2, value: 1 }),
                        (8, Instruction::Fallthrough),
                    ],
                    vec![10],
                ),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![20, 40],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::AddImm32 {
                                dst: 1,
                                src: 1,
                                value: 1,
                            },
                        ),
                        (24, Instruction::Fallthrough),
                    ],
                    vec![30],
                ),
                (
                    30,
                    vec![
                        (
                            30,
                            Instruction::Sub32 {
                                dst: 0,
                                src1: 0,
                                src2: 2,
                            },
                        ),
                        (34, Instruction::Jump { offset: -24 }),
                    ],
                    vec![10],
                ),
                (40, vec![(40, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        assert!(
            pseudo.contains("for ("),
            "Counting-down loop with Sub32 should be detected as for-loop: {}",
            pseudo
        );
        // Step should show subtraction
        assert!(
            pseudo.contains("var_0 = var_0 - var_2") || pseudo.contains("var_0 = var_0 - 1"),
            "For-header step should show subtraction: {}",
            pseudo
        );
    }

    #[test]
    fn test_function_signature_in_pseudo_code() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Function that uses r0 and r1 as parameters (live-in at entry):
        // block 0: r2 = r0 + r1, trap
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
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

        // Compute params from live_in
        let mut params: Vec<u8> = dataflow
            .live_in
            .get(&0)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        params.sort();

        let sig = FunctionSignature {
            name: "test_func".to_string(),
            params,
        };

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), Some(&sig));

        assert!(
            pseudo.contains("fn test_func("),
            "Should contain function declaration: {}",
            pseudo
        );
        // Body should be indented
        assert!(
            pseudo.contains("    "),
            "Body should be indented: {}",
            pseudo
        );
        // Should end with closing brace
        assert!(
            pseudo.trim_end().ends_with('}'),
            "Should end with closing brace: {}",
            pseudo
        );
        // r0 and r1 should be listed as parameters
        assert!(
            pseudo.contains("r0") || pseudo.contains("var_"),
            "Should list parameters: {}",
            pseudo
        );
    }

    #[test]
    fn test_function_signature_no_params() {
        // A function where no registers are live-in (self-contained)
        // block 0: r0 = 42, trap
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

        let sig = FunctionSignature {
            name: "no_params".to_string(),
            params: vec![],
        };

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, None, Some(&sig));

        assert!(
            pseudo.starts_with("fn no_params() {"),
            "Should have empty param list: {}",
            pseudo
        );
        assert!(
            pseudo.trim_end().ends_with('}'),
            "Should end with closing brace: {}",
            pseudo
        );
    }

    #[test]
    fn test_function_signature_with_loop() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Function with a loop: verify indentation stacks (body inside loop inside fn)
        // block 0: r0 = 0 (init), branch to block 8
        // block 8: branch_ne r0 1 → exit (12), fallthrough to block 8 (back-edge)
        // block 12: trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 0 }),
                        (4, Instruction::Jump { offset: 4 }),
                    ],
                    vec![8],
                ),
                (
                    8,
                    vec![(
                        8,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 1,
                            offset: 4,
                        },
                    )],
                    vec![12, 8],
                ),
                (12, vec![(12, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let sig = FunctionSignature {
            name: "loopy".to_string(),
            params: vec![],
        };

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), Some(&sig));

        assert!(
            pseudo.starts_with("fn loopy() {"),
            "Should start with fn header: {}",
            pseudo
        );
        // While loop should be indented inside fn body
        assert!(
            pseudo.contains("    while"),
            "While should be indented inside fn: {}",
            pseudo
        );
        // Return should be indented inside fn body
        assert!(
            pseudo.contains("    return"),
            "Return should be indented inside fn: {}",
            pseudo
        );
        assert!(
            pseudo.trim_end().ends_with('}'),
            "Should end with closing brace: {}",
            pseudo
        );
    }

    #[test]
    fn test_loop_with_latch_back_edge() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Simple loop: header branches to exit or body, body loops back to header.
        // block 0 (header): branch_ne r0 0 → 12 (exit), fallthrough to 4 (body/latch)
        // block 4 (body): r0 += r1, jump to 0 (back-edge)
        // block 12: trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 12,
                        },
                    )],
                    vec![12, 4],
                ),
                (
                    4,
                    vec![
                        (
                            4,
                            Instruction::Add32 {
                                dst: 0,
                                src1: 0,
                                src2: 1,
                            },
                        ),
                        (8, Instruction::Jump { offset: -8 }),
                    ],
                    vec![0],
                ),
                (12, vec![(12, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        // The body block jumps back to header (latch), no break here.
        // This is a normal while loop pattern.
        assert!(
            pseudo.contains("while"),
            "Should contain while loop: {}",
            pseudo
        );
    }

    #[test]
    fn test_break_via_if_in_loop() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Loop with conditional break:
        // block 0 (header): branch_ne r0 0 → 12 (exit), fallthrough to 4 (body)
        //   (condition: r0 != 0 → exit, so loop while r0 == 0... but body modifies r0)
        // block 4 (body1): r1 = r0, jump → 8
        // block 8 (body2/latch): back-edge to 0
        // block 12 (exit): trap
        //
        // In this structure, body1 has an if-then-else that targets exit → break.
        // Actually we need a structure where the structural analysis detects an if
        // inside the loop that branches to exit.
        //
        // Simpler: A body block that has 2 successors, one inside loop, one outside.
        // block 0 (header): branch r0 → 8 (exit), fallthrough to 4 (body)
        // block 4 (body): branch r1 → 8 (exit=break), fallthrough to 0 (header=continue)
        // block 8 (exit): trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 8,
                        },
                    )],
                    vec![8, 4],
                ),
                (
                    4,
                    vec![(
                        4,
                        Instruction::BranchNeImm {
                            reg: 1,
                            value: 0,
                            offset: 4,
                        },
                    )],
                    vec![8, 0],
                ),
                (8, vec![(8, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        // Block 4 is inside the loop and has a conditional branch to exit (8).
        // The structural analysis should detect this as an if inside the loop,
        // or at minimum, the block should show break when it exits.
        assert!(
            pseudo.contains("while") || pseudo.contains("for"),
            "Should contain loop: {}",
            pseudo
        );
        // The pseudo-code should show "break" somewhere for the exit path
        assert!(
            pseudo.contains("break"),
            "Should contain break for loop exit: {}",
            pseudo
        );
    }

    #[test]
    fn test_call_target_rendering() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Block 0: load r0 = 1, then Jump to 0x100 (a known function entry)
        // Block 10: trap (fallthrough successor, won't be reached in practice)
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 1 }),
                        (4, Instruction::Jump { offset: 0x100 - 4 }),
                    ],
                    vec![10],
                ),
                (10, vec![(10, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        // Register a call target: address 0x100 is "helper_func"
        lifted.call_targets.insert(0x100, "helper_func".to_string());

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        assert!(
            pseudo.contains("helper_func()"),
            "Should render Jump to known function as call: {}",
            pseudo
        );
    }

    #[test]
    fn test_indirect_call_rendering() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Block: load reg5 = 0x200, then JumpInd reg5
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
        lifted.call_targets.insert(0x200, "target_func".to_string());

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        assert!(
            pseudo.contains("target_func()"),
            "Should render JumpInd to known function as call: {}",
            pseudo
        );
    }

    #[test]
    fn test_suppress_unreachable_after_break() {
        // Loop with an if-then-else in the body where BOTH branches terminate:
        //   Block 0 (header): condition → body (10) or exit (60)
        //   Block 10: branch → 20 (continue) or 30 (break)
        //   Block 20: continues loop → header (emits "continue")
        //   Block 30: exits loop → 60 (emits "break")
        //   Block 40: only reachable from 10 via if-then-else, but BOTH branches
        //             terminate, so block 40 is unreachable — should be suppressed
        //   Block 50: latch, jumps back to 0
        //   Block 60: exit (trap)
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::BranchLtU {
                            reg1: 0,
                            reg2: 1,
                            offset: 10,
                        },
                    )],
                    vec![10, 60],
                ),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchEqImm {
                            reg: 2,
                            value: 0,
                            offset: 20,
                        },
                    )],
                    vec![20, 30],
                ),
                (
                    20,
                    vec![
                        (20, Instruction::LoadImm { reg: 3, value: 42 }),
                        (24, Instruction::Jump { offset: 0_i32 - 24 }),
                    ],
                    vec![0],
                ),
                (
                    30,
                    vec![
                        (30, Instruction::LoadImm { reg: 4, value: 99 }),
                        (
                            34,
                            Instruction::Jump {
                                offset: 60_i32 - 34,
                            },
                        ),
                    ],
                    vec![60],
                ),
                (
                    40,
                    vec![
                        (40, Instruction::LoadImm { reg: 5, value: 77 }),
                        (44, Instruction::Fallthrough),
                    ],
                    vec![50],
                ),
                (
                    50,
                    vec![(50, Instruction::Jump { offset: 0_i32 - 50 })],
                    vec![0],
                ),
                (60, vec![(60, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, None, None);

        // Should contain both break and continue
        assert!(pseudo.contains("break"), "Should contain break: {}", pseudo);
        assert!(
            pseudo.contains("continue"),
            "Should contain continue: {}",
            pseudo
        );

        // Block 40 loads r5=77 — this should be suppressed as unreachable
        // since both branches of the if-then-else terminate (break/continue).
        assert!(
            !pseudo.contains("r5 = 77"),
            "Unreachable block after break/continue should be suppressed: {}",
            pseudo
        );
    }

    #[test]
    fn test_topological_body_order_latch_before_inner_blocks() {
        // Regression test for #37: latch block at a lower PC than other body blocks.
        // Without topological ordering, the latch (PC 20) would be emitted before
        // the inner body block (PC 50), causing `continue` to appear mid-body.
        //
        //   Block 100 (header): branch → 50 or 200 (exit)
        //   Block 50: body logic, falls through to 20
        //   Block 20 (latch): jumps back to header (100) → emits `continue`
        //   Block 200: exit (trap)
        //
        // PC-sorted order: 20, 50 — would emit latch (with `continue`) before body
        // Topological order: 50, 20 — body first, then latch
        let cfg = build_test_cfg(
            100,
            vec![
                (
                    100,
                    vec![(
                        100,
                        Instruction::BranchLtU {
                            reg1: 0,
                            reg2: 1,
                            offset: 50_i32 - 100,
                        },
                    )],
                    vec![50, 200],
                ),
                (
                    50,
                    vec![
                        (50, Instruction::LoadImm { reg: 3, value: 42 }),
                        (54, Instruction::Fallthrough),
                    ],
                    vec![20],
                ),
                (
                    20,
                    vec![
                        (20, Instruction::LoadImm { reg: 4, value: 99 }),
                        (
                            24,
                            Instruction::Jump {
                                offset: 100_i32 - 24,
                            },
                        ),
                    ],
                    vec![100],
                ),
                (200, vec![(200, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, None, None);

        // Body block (r3 = 42) should appear BEFORE latch (r4 = 99 + continue)
        let body_pos = pseudo.find("r3 = 42").expect("body block should appear");
        let latch_pos = pseudo.find("r4 = 99").expect("latch block should appear");
        assert!(
            body_pos < latch_pos,
            "Body block should appear before latch block in output.\n\
             body_pos={}, latch_pos={}\nOutput:\n{}",
            body_pos,
            latch_pos,
            pseudo
        );

        // Redundant `continue` at end of loop body should be suppressed
        assert!(
            !pseudo.contains("continue"),
            "Redundant continue at end of loop body should be suppressed: {}",
            pseudo
        );
    }

    #[test]
    fn test_suppress_empty_else_block() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Diamond: header branches to then (10) or else (20), both join at 30.
        // Then-block has real content, else-block has only a Fallthrough
        // (which is skipped in lifted mode), so the `else` clause should be suppressed.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![10, 20],
                ),
                (
                    10,
                    vec![
                        (10, Instruction::LoadImm { reg: 1, value: 42 }),
                        (14, Instruction::Fallthrough),
                    ],
                    vec![30],
                ),
                (20, vec![(20, Instruction::Fallthrough)], vec![30]),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&mut lifted), None);

        // Should contain if with then content
        assert!(pseudo.contains("if"), "Should contain if: {}", pseudo);
        assert!(
            pseudo.contains("42"),
            "Should contain then block content: {}",
            pseudo
        );
        // Should NOT contain empty else clause
        assert!(
            !pseudo.contains("else"),
            "Empty else block should be suppressed: {}",
            pseudo
        );
    }

    #[test]
    fn test_conditional_branch_goto_rendering() {
        // Verify that real binary output uses `goto` labels
        // instead of raw `jump <offset>` for unstructured conditional branches.
        let bytes = std::fs::read("examples/compiled/as-fibonacci.pvm")
            .expect("as-fibonacci.pvm fixture required");
        let output =
            crate::decompile_bytes(&bytes).expect("as-fibonacci should decompile successfully");

        // Should contain at least one goto (unstructured conditional branches)
        assert!(
            output.contains("goto"),
            "Output should contain goto labels: {}",
            output
        );
        // No raw jump offsets should remain
        assert!(
            !output.contains("jump"),
            "Should not contain raw jump offsets: {}",
            output
        );
    }
}
