use super::{CondOp, Condition, Operand, StructuralAnalysis, Structure, extract_condition};
use crate::cfg::ControlFlowGraph;
use crate::instruction::InstructionShape;
use crate::lifting::{Expression, LiftedProgram};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use wasm_pvm::pvm::Instruction;

type DispatchSwitch<'a> = (u8, &'a [(Vec<u32>, usize)]);

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
        lifted: Option<&LiftedProgram>,
        sig: Option<&FunctionSignature>,
    ) -> String {
        let mut header_line = String::new();

        // Emit function header
        if let Some(sig) = sig {
            let params_str: Vec<String> = sig
                .params
                .iter()
                .map(|&reg| {
                    if let Some(lifted) = lifted {
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
        let mut dispatch_switch_map: HashMap<usize, &Structure> = HashMap::new();

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
                    if *is_dispatch {
                        dispatch_switch_map.insert(*header, s);
                    } else {
                        switch_map.insert(*header, s);
                    }
                }
            }
        }
        let mut switch_headers: HashSet<usize> = switch_map.keys().copied().collect();
        switch_headers.extend(dispatch_switch_map.keys().copied());

        let emission_plan = build_emission_plan(
            cfg,
            &self.structures,
            lifted,
            &self.dom_tree,
            &loop_map,
            &if_map,
        );

        let (declared_vars, hoisted_decls) = if let Some(lifted) = lifted {
            let hoisted = collect_hoisted_declarations(lifted, cfg);
            let mut declared = lifted.declared_vars.clone();
            for decl in &hoisted {
                declared.insert(decl.name.clone());
            }
            (declared, hoisted)
        } else {
            (HashSet::new(), Vec::new())
        };

        // Create the emitter with all mutable state.
        let mut em = Emitter {
            cfg,
            output: if sig.is_some() {
                String::new()
            } else {
                "=== Pseudo-Code ===\n\n".to_string()
            },
            emitted: HashSet::new(),
            reachable_blocks: self.dom_tree.rpo.iter().copied().collect(),
            lifted,
            labels,
            if_map,
            loop_map,
            switch_headers,
            plan: &emission_plan,
            declared_vars,
            dispatch_loop_header: None,
        };

        if !hoisted_decls.is_empty() {
            for decl in &hoisted_decls {
                if let Some(ref ty) = decl.var_type {
                    let _ = writeln!(em.output, "let {}: {}", decl.name, ty);
                } else {
                    let _ = writeln!(em.output, "let {}", decl.name);
                }
            }
            em.output.push('\n');
        }

        for &block_pc in &self.dom_tree.rpo {
            if em.emitted.contains(&block_pc) {
                continue;
            }

            let dispatch_switch: Option<DispatchSwitch<'_>> =
                dispatch_switch_map.get(&block_pc).and_then(|s| match *s {
                    Structure::Switch { reg, cases, .. } => Some((*reg, cases.as_slice())),
                    _ => None,
                });
            let render_dispatch_loop = dispatch_switch
                .as_ref()
                .is_some_and(|(_, cases)| em.should_emit_dispatch_loop(block_pc, cases));

            // Emit label if this block has one.
            if !render_dispatch_loop && let Some(label) = em.labels.get(&block_pc) {
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
            } else if let Some((reg, cases)) = dispatch_switch {
                if render_dispatch_loop {
                    em.emit_dispatch_loop(block_pc, reg, cases);
                } else {
                    em.emit_linear_region(block_pc, 0);
                }
            } else if let Some(Structure::Switch { reg, cases, .. }) = switch_map.get(&block_pc) {
                em.emit_switch(block_pc, *reg, cases, 0);
            } else {
                // Emit a linear plain region to avoid redundant goto-to-next-block noise.
                em.emit_linear_region(block_pc, 0);
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
struct Emitter<'a, 'p> {
    cfg: &'a ControlFlowGraph,
    output: String,
    emitted: HashSet<usize>,
    reachable_blocks: HashSet<usize>,
    lifted: Option<&'a LiftedProgram>,
    labels: HashMap<usize, String>,
    if_map: HashMap<usize, &'a Structure>,
    loop_map: HashMap<usize, &'a Structure>,
    switch_headers: HashSet<usize>,
    plan: &'p EmissionPlan,
    declared_vars: HashSet<String>,
    dispatch_loop_header: Option<usize>,
}

impl<'a, 'p> Emitter<'a, 'p> {
    /// Emit a maximal straight-line plain-block chain to reduce redundant gotos.
    fn emit_linear_region(&mut self, start_pc: usize, indent: usize) {
        let chain = self.collect_linear_region(start_pc);
        for (idx, &block_pc) in chain.iter().enumerate() {
            // Chained blocks have a single predecessor in the chain, so they
            // can be rendered as plain fallthrough without local labels.
            let mut fallthrough_target = chain.get(idx + 1).copied();
            if fallthrough_target.is_none()
                && let Some(block) = self.cfg.blocks.get(&block_pc)
                && block.successors.len() == 1
            {
                let succ = block.successors[0];
                // Allow fallthrough into an immediately emitted structured header
                // to avoid `goto label; label:` noise at region boundaries.
                if !self.emitted.contains(&succ)
                    && (self.loop_map.contains_key(&succ)
                        || self.if_map.contains_key(&succ)
                        || self.switch_headers.contains(&succ))
                {
                    fallthrough_target = Some(succ);
                }
            }
            self.emit_block_body_with_fallthrough(block_pc, indent, false, fallthrough_target);
            self.emitted.insert(block_pc);
        }
    }

    fn collect_linear_region(&self, start_pc: usize) -> Vec<usize> {
        let mut chain = vec![start_pc];
        let mut seen: HashSet<usize> = HashSet::from([start_pc]);
        let mut current = start_pc;

        loop {
            let Some(block) = self.cfg.blocks.get(&current) else {
                break;
            };
            if block.successors.len() != 1 {
                break;
            }
            let succ = block.successors[0];
            if !self.cfg.blocks.contains_key(&succ)
                || self.emitted.contains(&succ)
                || seen.contains(&succ)
                || self.loop_map.contains_key(&succ)
                || self.if_map.contains_key(&succ)
                || self.switch_headers.contains(&succ)
            {
                break;
            }

            let Some(succ_block) = self.cfg.blocks.get(&succ) else {
                break;
            };
            // Only chain into blocks with a single effective predecessor.
            // Ignore unreachable pure-fallthrough padding predecessors.
            let effective_pred_count = succ_block
                .predecessors
                .iter()
                .filter(|pred| {
                    self.reachable_blocks.contains(pred)
                        || !self.is_ignorable_unreachable_predecessor(**pred)
                })
                .count();
            if effective_pred_count != 1 {
                break;
            }

            chain.push(succ);
            seen.insert(succ);
            current = succ;
        }

        chain
    }

    fn is_ignorable_unreachable_predecessor(&self, pred_pc: usize) -> bool {
        if self.reachable_blocks.contains(&pred_pc) {
            return false;
        }
        let Some(block) = self.cfg.blocks.get(&pred_pc) else {
            return false;
        };
        block
            .instructions
            .iter()
            .all(|(_, instr)| matches!(instr, Instruction::Fallthrough))
    }

    fn emit_if(
        &mut self,
        header: usize,
        then_blocks: &[usize],
        else_blocks: &[usize],
        condition: Option<&Condition>,
        indent: usize,
        loop_context: Option<usize>,
    ) {
        let prefix = "    ".repeat(indent);
        let inner_prefix = "    ".repeat(indent + 1);

        // If all body blocks are suppressed, skip the entire if-structure.
        if self.plan.fully_suppressed_if_headers.contains(&header) {
            // Still emit the header body (non-branch instructions)
            self.emit_block_body(header, indent, true);
            for &tb in then_blocks {
                self.emitted.insert(tb);
            }
            for &eb in else_blocks {
                self.emitted.insert(eb);
            }
            self.emitted.insert(header);
            return;
        }

        // No-loop context: if both branches are guaranteed to emit nothing, skip shell.
        if loop_context.is_none() && self.plan.force_empty_if_headers_no_loop.contains(&header) {
            self.emit_block_body(header, indent, true);
            for &tb in then_blocks {
                self.emitted.insert(tb);
            }
            for &eb in else_blocks {
                self.emitted.insert(eb);
            }
            self.emitted.insert(header);
            return;
        }

        // Emit header block instructions (before the branch)
        self.emit_block_body(header, indent, true);

        let cond_str = condition
            .map(|c| {
                format_condition_maybe_lifted(
                    c,
                    self.cfg,
                    header,
                    self.lifted,
                    Some(&self.plan.emission_eliminated_pcs),
                )
            })
            .unwrap_or_else(|| "...".to_string());
        let cond_str = apply_aliases(&cond_str, &self.plan.var_aliases);
        let if_start = self.output.len();
        let _ = writeln!(self.output, "{}if ({}) {{", prefix, cond_str);
        let then_start = self.output.len();

        let has_then_content = if loop_context.is_none()
            && self.plan.empty_then_if_headers_no_loop.contains(&header)
        {
            for &tb in then_blocks {
                self.emitted.insert(tb);
            }
            false
        } else {
            for &tb in then_blocks {
                let ctrl = self.emit_block_with_loop_control(tb, indent + 1, loop_context);
                if let Some(keyword) = ctrl {
                    let _ = writeln!(self.output, "{}{}", inner_prefix, keyword);
                    self.emitted.insert(tb);
                    break; // Suppress unreachable blocks after break/continue
                }
                self.emitted.insert(tb);
            }
            self.output.len() > then_start
        };

        let mut has_else_content = false;
        if !else_blocks.is_empty() {
            // No-loop context: if else side is guaranteed empty, suppress it outright.
            if loop_context.is_none() && self.plan.empty_else_if_headers_no_loop.contains(&header) {
                // Mark else blocks as emitted but don't output them.
                for &eb in else_blocks {
                    self.emitted.insert(eb);
                }
            } else {
                // Emit else blocks into a temporary buffer to check if any content is produced.
                let else_insert_at = self.output.len();

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
                has_else_content = self.output.len() > else_insert_at;
                if has_else_content {
                    // Insert "} else {" before the else content
                    self.output
                        .insert_str(else_insert_at, &format!("{}}} else {{\n", prefix));
                }
            }
        }

        if has_then_content || has_else_content {
            let _ = writeln!(self.output, "{}}}", prefix);
        } else {
            // Avoid emitting hollow control-flow shells.
            self.output.truncate(if_start);
        }
        self.emitted.insert(header);
    }

    /// Emit a block body, detecting break/continue when inside a loop.
    /// Returns `Some("break")` or `Some("continue")` if the block exits/continues the loop.
    fn emit_block_with_loop_control(
        &mut self,
        block_pc: usize,
        indent: usize,
        loop_context: Option<usize>,
    ) -> Option<&'static str> {
        self.emit_block_with_loop_control_and_fallthrough(block_pc, indent, loop_context, None)
    }

    fn emit_block_with_loop_control_and_fallthrough(
        &mut self,
        block_pc: usize,
        indent: usize,
        loop_context: Option<usize>,
        fallthrough_target: Option<usize>,
    ) -> Option<&'static str> {
        if let Some(loop_header) = loop_context
            && let Some(action) = self.plan.loop_terminal_action(loop_header, block_pc)
        {
            self.emit_block_body(block_pc, indent, true);
            return Some(action.keyword());
        }
        self.emit_block_body_with_fallthrough(block_pc, indent, false, fallthrough_target);
        None
    }

    /// Emit the instructions in a block as pseudo-code lines.
    /// If `skip_terminator` is true, the last instruction (branch/jump) is not emitted.
    /// When `lifted` is provided, uses variable names and skips eliminated PCs.
    fn emit_block_body(&mut self, block_pc: usize, indent: usize, skip_terminator: bool) {
        self.emit_block_body_with_fallthrough(block_pc, indent, skip_terminator, None);
    }

    fn emit_block_body_with_fallthrough(
        &mut self,
        block_pc: usize,
        indent: usize,
        skip_terminator: bool,
        fallthrough_target: Option<usize>,
    ) {
        // Skip blocks that are entirely suppressed (e.g., callee code misassigned to caller)
        if let Some(lifted) = self.lifted
            && lifted.suppressed_blocks.contains(&block_pc)
        {
            return;
        }
        let prefix = "    ".repeat(indent);
        let len_before = self.output.len();
        let mut block_reg_values: HashMap<u8, String> = HashMap::new();
        if let Some(block) = self.cfg.blocks.get(&block_pc) {
            let len = block.instructions.len();
            let end = if skip_terminator && len > 0 {
                len - 1
            } else {
                len
            };

            for (pc, instr) in &block.instructions[..end] {
                if let Some(lifted) = self.lifted {
                    if let Some((reg, value)) = register_value_after_instruction(
                        lifted,
                        *pc,
                        instr,
                        &self.plan.emission_eliminated_pcs,
                        &self.plan.var_aliases,
                    ) {
                        block_reg_values.insert(reg, value);
                    }
                    // Skip eliminated PCs (folded/propagated).
                    if lifted.eliminated_pcs.contains(pc)
                        || self.plan.emission_eliminated_pcs.contains(pc)
                    {
                        continue;
                    }
                    // Check if this Jump is a function call
                    if let Instruction::Jump { offset } = instr {
                        if let Some(callee) = lifted.direct_call_sites.get(pc).cloned() {
                            let line = format_named_call(
                                lifted,
                                &callee,
                                *pc,
                                &block_reg_values,
                                &self.plan.var_aliases,
                                &self.plan.emission_eliminated_pcs,
                            );
                            let _ = writeln!(self.output, "{}{}", prefix, line);
                            continue;
                        }
                        let target =
                            crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                        if let Some(callee) = lifted.call_targets.get(&target) {
                            let line = format_named_call(
                                lifted,
                                callee,
                                *pc,
                                &block_reg_values,
                                &self.plan.var_aliases,
                                &self.plan.emission_eliminated_pcs,
                            );
                            let _ = writeln!(self.output, "{}{}", prefix, line);
                            continue;
                        }
                        if Some(target) == fallthrough_target {
                            continue;
                        }
                        if Some(target) == self.dispatch_loop_header {
                            let _ = writeln!(self.output, "{}continue", prefix);
                            continue;
                        }
                        let target_label = self
                            .labels
                            .get(&target)
                            .cloned()
                            .unwrap_or_else(|| format!("block_{:04x}", target));
                        let _ = writeln!(self.output, "{}goto {};", prefix, target_label);
                        continue;
                    }
                    // Check if this JumpInd targets a known function entry
                    if let Instruction::JumpInd { reg, .. } = instr {
                        // First try: resolve register to a constant PC in call_targets
                        if let Some(callee) = lifted.resolve_indirect_call(*pc, *reg) {
                            let line = format_named_call(
                                lifted,
                                &callee,
                                *pc,
                                &block_reg_values,
                                &self.plan.var_aliases,
                                &self.plan.emission_eliminated_pcs,
                            );
                            let _ = writeln!(self.output, "{}{}", prefix, line);
                            continue;
                        }
                        // Unresolved indirect jumps are rendered explicitly.
                        if let Some(line) = format_pc_with_local_declarations(
                            lifted,
                            *pc,
                            instr,
                            &mut self.declared_vars,
                            &self.plan.var_aliases,
                        ) {
                            let _ = writeln!(self.output, "{}{}", prefix, line);
                        }
                        continue;
                    }
                    // Skip noise instructions in lifted mode.
                    if matches!(instr, Instruction::Fallthrough) {
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
                            format_condition_maybe_lifted(
                                &cond,
                                self.cfg,
                                block_pc,
                                Some(lifted),
                                Some(&self.plan.emission_eliminated_pcs),
                            )
                        } else {
                            "...".to_string()
                        };
                        let cond_str = apply_aliases(&cond_str, &self.plan.var_aliases);
                        if Some(target) == self.dispatch_loop_header {
                            let _ = writeln!(self.output, "{}if ({}) continue;", prefix, cond_str);
                        } else {
                            let _ = writeln!(
                                self.output,
                                "{}if ({}) goto {};",
                                prefix, cond_str, target_label
                            );
                        }
                        continue;
                    }
                    if let Some(line) = format_pc_with_local_declarations(
                        lifted,
                        *pc,
                        instr,
                        &mut self.declared_vars,
                        &self.plan.var_aliases,
                    ) {
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
        if let Some(lifted) = self.lifted
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
        let (
            non_header_body,
            lifted_suppressed_non_header,
            body_ordered,
            reachable,
            last_emittable,
            force_empty_body,
            empty_body_fallback,
        ) = if let Some(plan) = self.plan.loop_plans.get(&header_pc) {
            (
                plan.non_header_body.clone(),
                plan.lifted_suppressed_non_header.clone(),
                plan.body_order.clone(),
                plan.reachable.clone(),
                plan.last_emittable,
                plan.force_empty_body,
                plan.empty_body_fallback,
            )
        } else {
            // Should not happen in normal flow: every loop header comes from `loop_map`
            // and has a precomputed plan entry.
            let mut non_header_body: Vec<usize> =
                body.iter().copied().filter(|&bp| bp != header_pc).collect();
            non_header_body.sort();
            let reachable: HashSet<usize> = non_header_body.iter().copied().collect();
            let body_ordered = non_header_body.clone();
            let last_emittable = body_ordered.last().copied();
            (
                non_header_body,
                HashSet::new(),
                body_ordered,
                reachable,
                last_emittable,
                false,
                EmptyLoopFallback::EmitContinue,
            )
        };

        // Suppress loops whose body blocks are all already emitted or suppressed.
        // This happens when callee blocks get assigned to the caller but are not
        // actually part of the caller's logic. Self-loops (body = {header}) are
        // always rendered since they represent genuine tight loops.
        let has_unemitted_body = non_header_body.is_empty()
            || non_header_body
                .iter()
                .any(|bp| !self.emitted.contains(bp) && !lifted_suppressed_non_header.contains(bp));
        if !has_unemitted_body {
            // Mark all body blocks as emitted so they don't get rendered as top-level blocks.
            self.emitted.insert(header_pc);
            self.emitted.extend(body.iter());
            // Still emit the header block's non-branch instructions (they may have side effects).
            self.emit_block_body(header_pc, indent, true);
            return;
        }

        // Save output position before the loop, so we can rewind if the
        // loop body turns out to be empty (all blocks produce no visible output).
        let output_before_loop = self.output.len();

        let prefix = "    ".repeat(indent);
        let render_condition = condition
            .as_ref()
            .map(|c| maybe_invert_loop_condition(self.cfg, header_pc, body, c));
        let cond_str = render_condition
            .as_ref()
            .map(|c| {
                format_condition_maybe_lifted(
                    c,
                    self.cfg,
                    header_pc,
                    self.lifted,
                    Some(&self.plan.emission_eliminated_pcs),
                )
            })
            .unwrap_or_else(|| "...".to_string());
        let cond_str = apply_aliases(&cond_str, &self.plan.var_aliases);

        // Clone for-loop info to avoid holding a borrow of plan data
        // across mutable self calls.
        let for_loop_info = self.plan.for_loop_map.get(&header_pc).cloned();

        if let Some(ref info) = for_loop_info {
            let init_str = apply_aliases(&info.init_str, &self.plan.var_aliases);
            let step_str = apply_aliases(&info.step_str, &self.plan.var_aliases);
            let _ = writeln!(
                self.output,
                "{}for ({}; {}; {}) {{",
                prefix, init_str, cond_str, step_str
            );
        } else {
            let _ = writeln!(self.output, "{}while ({}) {{", prefix, cond_str);
        }
        // Emit header block body (before the condition branch)
        self.emit_block_body(header_pc, indent + 1, true);

        for (idx, &body_pc) in body_ordered.iter().enumerate() {
            if body_pc == header_pc || self.emitted.contains(&body_pc) {
                continue;
            }

            // Skip blocks that are unreachable from the header through non-terminal paths.
            if !reachable.contains(&body_pc) {
                self.emitted.insert(body_pc);
                continue;
            }

            let is_latch = body_pc == latch && for_loop_info.is_some();

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
                    Some(header_pc),
                );
                continue;
            }

            let inner_prefix = "    ".repeat(indent + 1);
            let fallthrough_target = body_ordered[idx + 1..].iter().copied().find(|next| {
                *next != header_pc
                    && reachable.contains(next)
                    && !self.emitted.contains(next)
                    && !lifted_suppressed_non_header.contains(next)
            });
            if is_latch {
                self.emit_block_body_with_fallthrough(
                    body_pc,
                    indent + 1,
                    true,
                    fallthrough_target,
                );
            } else {
                let ctrl = self.emit_block_with_loop_control_and_fallthrough(
                    body_pc,
                    indent + 1,
                    Some(header_pc),
                    fallthrough_target,
                );
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

        // Empty-loop fallback policy is precomputed in analysis planning.
        if force_empty_body {
            match empty_body_fallback {
                EmptyLoopFallback::CollapseToHeaderSideEffects => {
                    self.output.truncate(output_before_loop);
                    self.emit_block_body(header_pc, indent, true);
                }
                EmptyLoopFallback::EmitContinue => {
                    let inner_prefix = "    ".repeat(indent + 1);
                    let _ = writeln!(self.output, "{}continue", inner_prefix);
                    let _ = writeln!(self.output, "{}}}", prefix);
                }
            }
        } else {
            let _ = writeln!(self.output, "{}}}", prefix);
        }
        self.emitted.extend(body.iter());
    }

    /// Emit a switch/case structure.
    fn emit_switch(
        &mut self,
        block_pc: usize,
        reg: u8,
        cases: &[(Vec<u32>, usize)],
        indent: usize,
    ) {
        self.emit_block_body(block_pc, indent, true);
        let prefix = "    ".repeat(indent);
        let case_prefix = "    ".repeat(indent + 1);

        let switch_var = if let Some(lifted) = self.lifted {
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
                    if has_local_def && self.declared_vars.insert(name.clone()) {
                        let type_str = lifted
                            .variables
                            .values()
                            .find(|v| v.name == name)
                            .map(|v| format!("{}", v.var_type))
                            .unwrap_or_else(|| "u64".to_string());
                        let _ = writeln!(self.output, "{}let {}: {};", prefix, name, type_str);
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
        let switch_var = apply_aliases(&switch_var, &self.plan.var_aliases);
        let _ = writeln!(self.output, "{}switch ({}) {{", prefix, switch_var);
        for (values, target) in cases.iter() {
            let vals: Vec<String> = values.iter().map(|v| format!("{}", v)).collect();
            if Some(*target) == self.dispatch_loop_header {
                let _ = writeln!(
                    self.output,
                    "{}case {}: continue;",
                    case_prefix,
                    vals.join(", ")
                );
                continue;
            }
            let target_label = format_goto_target(*target, &self.labels);
            let _ = writeln!(
                self.output,
                "{}case {}: goto {};",
                case_prefix,
                vals.join(", "),
                target_label
            );
        }
        let _ = writeln!(self.output, "{}}}", prefix);
        self.emitted.insert(block_pc);
    }

    /// True when switch cases contain a meaningful back-edge region to structure
    /// as `loop { switch { ... } }`.
    fn should_emit_dispatch_loop(&self, header_pc: usize, cases: &[(Vec<u32>, usize)]) -> bool {
        let Some(header_block) = self.cfg.blocks.get(&header_pc) else {
            return false;
        };
        let header_succs: HashSet<usize> = header_block.successors.iter().copied().collect();

        let mut roots: Vec<usize> = cases.iter().map(|(_, target)| *target).collect();
        roots.sort_unstable();
        roots.dedup();
        roots.retain(|target| {
            *target != header_pc
                && self.cfg.blocks.contains_key(target)
                && header_succs.contains(target)
                && !self.emitted.contains(target)
        });
        if roots.len() < 2 {
            return false;
        }

        let mut visited: HashSet<usize> = HashSet::new();
        let mut queue: VecDeque<usize> = roots.into_iter().collect();
        while let Some(pc) = queue.pop_front() {
            if !visited.insert(pc) {
                continue;
            }
            if let Some(block) = self.cfg.blocks.get(&pc) {
                for &succ in &block.successors {
                    if succ == header_pc {
                        return true;
                    }
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }

        false
    }

    /// Emit dispatch infrastructure as `loop { switch { ... } }`.
    fn emit_dispatch_loop(&mut self, header_pc: usize, reg: u8, cases: &[(Vec<u32>, usize)]) {
        let header_succs: HashSet<usize> = self
            .cfg
            .blocks
            .get(&header_pc)
            .map(|b| b.successors.iter().copied().collect())
            .unwrap_or_default();
        let local_cases: Vec<(Vec<u32>, usize)> = cases
            .iter()
            .filter(|(_, target)| {
                self.cfg.blocks.contains_key(target)
                    && (*target == header_pc
                        || (header_succs.contains(target) && !self.emitted.contains(target)))
            })
            .cloned()
            .collect();
        if local_cases.is_empty() {
            self.emit_linear_region(header_pc, 0);
            return;
        }

        let _ = writeln!(self.output, "loop {{");
        let previous_header = self.dispatch_loop_header.replace(header_pc);
        self.emit_switch(header_pc, reg, &local_cases, 1);
        self.emit_dispatch_targets(header_pc, &local_cases, 1);
        self.dispatch_loop_header = previous_header;
        let _ = writeln!(self.output, "}}");
    }

    /// Emit case target regions for a dispatch loop.
    fn emit_dispatch_targets(
        &mut self,
        dispatch_header: usize,
        cases: &[(Vec<u32>, usize)],
        indent: usize,
    ) {
        let prefix = "    ".repeat(indent);
        let mut roots: Vec<usize> = cases.iter().map(|(_, target)| *target).collect();
        roots.sort_unstable();
        roots.dedup();

        for target_pc in roots {
            if target_pc == dispatch_header
                || self.emitted.contains(&target_pc)
                || !self.cfg.blocks.contains_key(&target_pc)
            {
                continue;
            }
            let _ = writeln!(
                self.output,
                "{}{}:",
                prefix,
                self.label_for_target(target_pc)
            );

            let mut reachable = Vec::new();
            let mut visited: HashSet<usize> = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(target_pc);

            while let Some(pc) = queue.pop_front() {
                if pc == dispatch_header || !visited.insert(pc) || self.emitted.contains(&pc) {
                    continue;
                }
                reachable.push(pc);
                self.emitted.insert(pc);
                if let Some(block) = self.cfg.blocks.get(&pc) {
                    for &succ in &block.successors {
                        if succ != dispatch_header
                            && !visited.contains(&succ)
                            && !self.emitted.contains(&succ)
                        {
                            queue.push_back(succ);
                        }
                    }
                }
            }

            for &block_pc in &reachable {
                if block_pc != target_pc
                    && let Some(label) = self.labels.get(&block_pc)
                {
                    let _ = writeln!(self.output, "{}{}:", prefix, label);
                }

                if let Some(Structure::Loop {
                    body,
                    latch,
                    condition,
                    ..
                }) = self.loop_map.get(&block_pc)
                {
                    self.emit_loop(block_pc, body, *latch, condition, indent);
                } else if let Some(Structure::IfThenElse {
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
                        indent,
                        None,
                    );
                } else {
                    self.emit_block_body(block_pc, indent, false);
                }
            }
        }
    }

    fn label_for_target(&self, target: usize) -> String {
        self.labels
            .get(&target)
            .cloned()
            .unwrap_or_else(|| format!("block_{:04x}", target))
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

struct EmissionPlan {
    for_loop_map: HashMap<usize, ForLoopInfo>,
    emission_eliminated_pcs: HashSet<usize>,
    var_aliases: HashMap<String, String>,
    loop_plans: HashMap<usize, LoopRenderPlan>,
    fully_suppressed_if_headers: HashSet<usize>,
    empty_then_if_headers_no_loop: HashSet<usize>,
    empty_else_if_headers_no_loop: HashSet<usize>,
    force_empty_if_headers_no_loop: HashSet<usize>,
}

impl EmissionPlan {
    fn loop_terminal_action(
        &self,
        loop_header: usize,
        block_pc: usize,
    ) -> Option<LoopTerminalAction> {
        self.loop_plans
            .get(&loop_header)
            .and_then(|p| p.terminal_actions.get(&block_pc))
            .copied()
    }
}

#[derive(Clone)]
struct LoopRenderPlan {
    non_header_body: Vec<usize>,
    lifted_suppressed_non_header: HashSet<usize>,
    body_order: Vec<usize>,
    reachable: HashSet<usize>,
    last_emittable: Option<usize>,
    force_empty_body: bool,
    empty_body_fallback: EmptyLoopFallback,
    terminal_actions: HashMap<usize, LoopTerminalAction>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum LoopTerminalAction {
    Break,
    Continue,
}

impl LoopTerminalAction {
    fn keyword(self) -> &'static str {
        match self {
            Self::Break => "break",
            Self::Continue => "continue",
        }
    }
}

#[derive(Copy, Clone)]
enum EmptyLoopFallback {
    CollapseToHeaderSideEffects,
    EmitContinue,
}

fn build_emission_plan<'a>(
    cfg: &ControlFlowGraph,
    structures: &[Structure],
    lifted: Option<&LiftedProgram>,
    dom_tree: &super::DominatorTree,
    loop_map: &HashMap<usize, &'a Structure>,
    if_map: &HashMap<usize, &'a Structure>,
) -> EmissionPlan {
    // Precompute all semantic suppression and aliasing decisions outside of `Emitter`.
    let mut for_loop_map: HashMap<usize, ForLoopInfo> = HashMap::new();
    let mut emission_eliminated_pcs: HashSet<usize> = HashSet::new();
    let mut var_aliases: HashMap<String, String> = HashMap::new();
    let mut fully_suppressed_if_headers: HashSet<usize> = HashSet::new();
    let mut empty_then_if_headers_no_loop: HashSet<usize> = HashSet::new();
    let mut empty_else_if_headers_no_loop: HashSet<usize> = HashSet::new();
    let mut force_empty_if_headers_no_loop: HashSet<usize> = HashSet::new();

    for s in structures {
        match s {
            Structure::Loop {
                header,
                body,
                latch,
                condition,
                ..
            } => {
                if let Some(info) =
                    detect_for_loop_pattern(cfg, *header, *latch, body, condition.as_ref(), lifted)
                {
                    let mut info = info;
                    // Suppress the init instruction from its block's normal emission.
                    emission_eliminated_pcs.insert(info.init_pc);
                    if let Some(lifted_ro) = lifted {
                        // Keep for-loop naming coherent without mutating LiftedProgram.
                        let init_name = lifted_ro
                            .variables
                            .get(&(info.init_pc, info.cond_reg))
                            .map(|v| v.name.clone());
                        let step_name = lifted_ro
                            .variables
                            .get(&(info.step_pc, info.cond_reg))
                            .map(|v| v.name.clone());
                        if let (Some(init_name), Some(step_name)) = (&init_name, &step_name)
                            && init_name != step_name
                        {
                            var_aliases.insert(step_name.clone(), init_name.clone());
                            info.step_str =
                                replace_identifier(&info.step_str, step_name, init_name);
                        }
                    }
                    for_loop_map.insert(*header, info);
                }
            }
            Structure::IfThenElse {
                header,
                then_blocks,
                else_blocks,
                ..
            } => {
                if !then_blocks.is_empty()
                    && lifted.is_some_and(|l| {
                        then_blocks
                            .iter()
                            .chain(else_blocks.iter())
                            .all(|bp| l.suppressed_blocks.contains(bp))
                    })
                {
                    fully_suppressed_if_headers.insert(*header);
                }
            }
            _ => {}
        }
    }

    // For-loop step is rendered in the for-header; suppress it from body emission.
    for info in for_loop_map.values() {
        emission_eliminated_pcs.insert(info.step_pc);
    }

    let pc_to_block = build_pc_to_block_index(cfg);
    let mut var_use_count: HashMap<String, usize> = HashMap::new();
    if let Some(lifted_ro) = lifted {
        for name in lifted_ro.var_at_use.values() {
            *var_use_count.entry(name.clone()).or_insert(0) += 1;
        }
        for (&(_def_pc, reg), var) in &lifted_ro.variables {
            if !var.name.starts_with("var_") {
                continue;
            }
            if var_use_count.get(&var.name).copied().unwrap_or(0) == 0 {
                var_aliases
                    .entry(var.name.clone())
                    .or_insert_with(|| format!("r{}", reg));
            }
        }
    }
    emission_eliminated_pcs.extend(collect_condition_elimination_pcs(
        structures,
        cfg,
        lifted,
        dom_tree,
        &pc_to_block,
        &var_use_count,
    ));

    let static_refs = EmissionStaticRefs {
        cfg,
        if_map,
        loop_map,
        lifted,
        emission_eliminated_pcs: &emission_eliminated_pcs,
    };
    for s in structures {
        let Structure::IfThenElse {
            header,
            then_blocks,
            else_blocks,
            ..
        } = s
        else {
            continue;
        };

        let then_empty = blocks_guaranteed_no_output_no_loop(&static_refs, then_blocks);
        if then_empty {
            empty_then_if_headers_no_loop.insert(*header);
        }

        let else_empty = else_blocks.is_empty()
            || else_blocks.iter().all(|&bp| is_trap_only_block(cfg, bp))
            || blocks_guaranteed_no_output_no_loop(&static_refs, else_blocks);
        if !else_blocks.is_empty() && else_empty {
            empty_else_if_headers_no_loop.insert(*header);
        }

        if then_empty && else_empty {
            force_empty_if_headers_no_loop.insert(*header);
        }
    }

    let mut loop_plans = HashMap::new();
    for (&header_pc, structure) in loop_map {
        let Structure::Loop { body, latch, .. } = *structure else {
            continue;
        };
        let mut terminal_actions = HashMap::new();
        for &block_pc in cfg.blocks.keys() {
            if let Some(action) = loop_terminal_action(cfg, block_pc, body, header_pc) {
                terminal_actions.insert(block_pc, action);
            }
        }

        let mut non_header_body: Vec<usize> =
            body.iter().copied().filter(|&bp| bp != header_pc).collect();
        non_header_body.sort();
        let lifted_suppressed_non_header: HashSet<usize> = lifted
            .map(|l| {
                non_header_body
                    .iter()
                    .copied()
                    .filter(|bp| l.suppressed_blocks.contains(bp))
                    .collect()
            })
            .unwrap_or_default();
        let body_order = compute_loop_body_order(cfg, if_map, body, header_pc);
        let reachable = compute_loop_reachable(cfg, if_map, body, header_pc);
        let emittable_order: Vec<usize> = body_order
            .iter()
            .copied()
            .filter(|&pc| pc != header_pc && reachable.contains(&pc))
            .collect();
        let last_emittable = emittable_order.last().copied();

        let static_refs = EmissionStaticRefs {
            cfg,
            if_map,
            loop_map,
            lifted,
            emission_eliminated_pcs: &emission_eliminated_pcs,
        };
        let plan_inputs = LoopPlanInputs {
            header_pc,
            latch_pc: *latch,
            has_for_latch: for_loop_map.contains_key(&header_pc),
            body_order: &body_order,
            reachable: &reachable,
            last_emittable,
            terminal_actions: &terminal_actions,
        };
        let force_empty_body = is_force_empty_loop_body(&static_refs, &plan_inputs);
        let empty_body_fallback = if non_header_body.len() > 3 {
            EmptyLoopFallback::CollapseToHeaderSideEffects
        } else {
            EmptyLoopFallback::EmitContinue
        };

        loop_plans.insert(
            header_pc,
            LoopRenderPlan {
                non_header_body,
                lifted_suppressed_non_header,
                body_order,
                reachable,
                last_emittable,
                force_empty_body,
                empty_body_fallback,
                terminal_actions,
            },
        );
    }

    EmissionPlan {
        for_loop_map,
        emission_eliminated_pcs,
        var_aliases,
        loop_plans,
        fully_suppressed_if_headers,
        empty_then_if_headers_no_loop,
        empty_else_if_headers_no_loop,
        force_empty_if_headers_no_loop,
    }
}

fn loop_terminal_action(
    cfg: &ControlFlowGraph,
    block_pc: usize,
    body: &HashSet<usize>,
    header_pc: usize,
) -> Option<LoopTerminalAction> {
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
        if is_trap {
            None
        } else if exits_loop {
            Some(LoopTerminalAction::Break)
        } else if continues_loop {
            Some(LoopTerminalAction::Continue)
        } else {
            None
        }
    } else {
        None
    }
}

fn is_trap_only_block(cfg: &ControlFlowGraph, block_pc: usize) -> bool {
    cfg.blocks.get(&block_pc).is_some_and(|b| {
        b.instructions.len() == 1 && matches!(b.instructions[0].1, Instruction::Trap)
    })
}

struct EmissionStaticRefs<'a, 's> {
    cfg: &'a ControlFlowGraph,
    if_map: &'a HashMap<usize, &'s Structure>,
    loop_map: &'a HashMap<usize, &'s Structure>,
    lifted: Option<&'a LiftedProgram>,
    emission_eliminated_pcs: &'a HashSet<usize>,
}

struct LoopPlanInputs<'a> {
    header_pc: usize,
    latch_pc: usize,
    has_for_latch: bool,
    body_order: &'a [usize],
    reachable: &'a HashSet<usize>,
    last_emittable: Option<usize>,
    terminal_actions: &'a HashMap<usize, LoopTerminalAction>,
}

fn is_force_empty_loop_body(
    refs: &EmissionStaticRefs<'_, '_>,
    inputs: &LoopPlanInputs<'_>,
) -> bool {
    // Header non-branch side effects are part of loop body rendering.
    if block_may_emit_output(
        refs.cfg,
        refs.lifted,
        refs.emission_eliminated_pcs,
        inputs.header_pc,
        /* skip_terminator */ true,
    ) {
        return false;
    }

    for &body_pc in inputs.body_order {
        if body_pc == inputs.header_pc || !inputs.reachable.contains(&body_pc) {
            continue;
        }

        // Nested structures are treated as non-empty unless proven otherwise.
        if refs.loop_map.contains_key(&body_pc) || refs.if_map.contains_key(&body_pc) {
            return false;
        }

        let is_latch = body_pc == inputs.latch_pc && inputs.has_for_latch;
        if is_latch {
            if block_may_emit_output(
                refs.cfg,
                refs.lifted,
                refs.emission_eliminated_pcs,
                body_pc,
                /* skip_terminator */ true,
            ) {
                return false;
            }
            continue;
        }

        if let Some(action) = inputs.terminal_actions.get(&body_pc).copied() {
            if block_may_emit_output(
                refs.cfg,
                refs.lifted,
                refs.emission_eliminated_pcs,
                body_pc,
                /* skip_terminator */ true,
            ) {
                return false;
            }
            let emits_keyword =
                !(action == LoopTerminalAction::Continue && inputs.last_emittable == Some(body_pc));
            if emits_keyword {
                return false;
            }
            continue;
        }

        if block_may_emit_output(
            refs.cfg,
            refs.lifted,
            refs.emission_eliminated_pcs,
            body_pc,
            /* skip_terminator */ false,
        ) {
            return false;
        }
    }

    true
}

fn block_may_emit_output(
    cfg: &ControlFlowGraph,
    lifted: Option<&LiftedProgram>,
    emission_eliminated_pcs: &HashSet<usize>,
    block_pc: usize,
    skip_terminator: bool,
) -> bool {
    if let Some(lifted) = lifted
        && lifted.suppressed_blocks.contains(&block_pc)
    {
        return false;
    }

    let Some(block) = cfg.blocks.get(&block_pc) else {
        return false;
    };

    let len = block.instructions.len();
    let end = if skip_terminator && len > 0 {
        len - 1
    } else {
        len
    };

    if let Some(lifted) = lifted {
        for (pc, instr) in &block.instructions[..end] {
            if lifted.eliminated_pcs.contains(pc) || emission_eliminated_pcs.contains(pc) {
                continue;
            }

            if matches!(instr, Instruction::Fallthrough) {
                continue;
            }

            if let Instruction::Jump { offset } = instr {
                if lifted.direct_call_sites.contains_key(pc) {
                    return true;
                }
                let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                if lifted.call_targets.contains_key(&target) {
                    return true;
                }
                return true;
            }

            if matches!(instr, Instruction::JumpInd { .. }) {
                return true;
            }

            let shape = InstructionShape::classify(instr);
            if shape.is_conditional_branch() {
                return true;
            }

            if lifted.format_pc_raw(*pc, instr).is_some() {
                return true;
            }
        }

        if lifted.epilogue_blocks.contains_key(&block_pc) {
            return true;
        }

        false
    } else {
        end > 0
    }
}

fn blocks_guaranteed_no_output_no_loop(
    refs: &EmissionStaticRefs<'_, '_>,
    blocks: &[usize],
) -> bool {
    blocks.iter().all(|&block_pc| {
        if refs.loop_map.contains_key(&block_pc) || refs.if_map.contains_key(&block_pc) {
            return false;
        }
        !block_may_emit_output(
            refs.cfg,
            refs.lifted,
            refs.emission_eliminated_pcs,
            block_pc,
            false,
        )
    })
}

fn if_branches<'a>(
    if_map: &HashMap<usize, &'a Structure>,
    block_pc: usize,
) -> Option<(&'a [usize], &'a [usize])> {
    let structure = if_map.get(&block_pc)?;
    if let Structure::IfThenElse {
        then_blocks,
        else_blocks,
        ..
    } = *structure
    {
        return Some((then_blocks, else_blocks));
    }
    None
}

/// Compute a topological ordering of body blocks using reverse post-order DFS.
/// This keeps loop body emission in control-flow order.
fn compute_loop_body_order(
    cfg: &ControlFlowGraph,
    if_map: &HashMap<usize, &Structure>,
    body: &HashSet<usize>,
    header_pc: usize,
) -> Vec<usize> {
    let mut visited = HashSet::new();
    let mut post_order = Vec::new();

    if let Some(header_block) = cfg.blocks.get(&header_pc) {
        let mut succs: Vec<usize> = header_block
            .successors
            .iter()
            .copied()
            .filter(|s| body.contains(s) && *s != header_pc)
            .collect();
        succs.sort();
        for succ in succs {
            dfs_loop_body_order(
                cfg,
                if_map,
                succ,
                body,
                header_pc,
                &mut visited,
                &mut post_order,
            );
        }
    }

    post_order.reverse();
    post_order
}

fn dfs_loop_body_order(
    cfg: &ControlFlowGraph,
    if_map: &HashMap<usize, &Structure>,
    pc: usize,
    body: &HashSet<usize>,
    header_pc: usize,
    visited: &mut HashSet<usize>,
    post_order: &mut Vec<usize>,
) {
    if !visited.insert(pc) {
        return;
    }

    if let Some(block) = cfg.blocks.get(&pc) {
        let mut succs: Vec<usize> = block
            .successors
            .iter()
            .copied()
            .filter(|s| body.contains(s) && *s != header_pc)
            .collect();
        succs.sort();
        for succ in succs {
            dfs_loop_body_order(cfg, if_map, succ, body, header_pc, visited, post_order);
        }
    }

    if let Some((then_blocks, else_blocks)) = if_branches(if_map, pc) {
        let mut branches: Vec<usize> = then_blocks
            .iter()
            .chain(else_blocks.iter())
            .copied()
            .filter(|b| body.contains(b) && *b != header_pc)
            .collect();
        branches.sort();
        for branch_pc in branches {
            dfs_loop_body_order(cfg, if_map, branch_pc, body, header_pc, visited, post_order);
        }
    }

    post_order.push(pc);
}

/// Compute loop-body reachability while stopping traversal past terminal
/// break/continue blocks and fully-terminal if/else forks.
fn compute_loop_reachable(
    cfg: &ControlFlowGraph,
    if_map: &HashMap<usize, &Structure>,
    body: &HashSet<usize>,
    header_pc: usize,
) -> HashSet<usize> {
    let mut reachable = HashSet::new();
    let mut worklist = VecDeque::new();

    if let Some(header_block) = cfg.blocks.get(&header_pc) {
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

        let is_terminal = loop_terminal_action(cfg, pc, body, header_pc).is_some();
        let if_terminates = if let Some((then_blocks, else_blocks)) = if_branches(if_map, pc) {
            let all_then_terminal = then_blocks
                .iter()
                .all(|&tb| loop_terminal_action(cfg, tb, body, header_pc).is_some());
            let all_else_terminal = else_blocks
                .iter()
                .all(|&eb| loop_terminal_action(cfg, eb, body, header_pc).is_some());
            !then_blocks.is_empty()
                && !else_blocks.is_empty()
                && all_then_terminal
                && all_else_terminal
        } else {
            false
        };

        if is_terminal || if_terminates {
            continue;
        }

        if let Some(block) = cfg.blocks.get(&pc) {
            for &succ in &block.successors {
                if body.contains(&succ) && succ != header_pc {
                    worklist.push_back(succ);
                }
            }
        }

        if let Some((then_blocks, else_blocks)) = if_branches(if_map, pc) {
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

fn collect_condition_elimination_pcs(
    structures: &[Structure],
    cfg: &ControlFlowGraph,
    lifted: Option<&LiftedProgram>,
    dom_tree: &super::DominatorTree,
    pc_to_block: &HashMap<usize, usize>,
    var_use_count: &HashMap<String, usize>,
) -> HashSet<usize> {
    let mut eliminated = HashSet::new();

    for s in structures {
        let (header_pc, condition) = match s {
            Structure::Loop {
                header, condition, ..
            } => (*header, condition.as_ref()),
            Structure::IfThenElse {
                header, condition, ..
            } => (*header, condition.as_ref()),
            _ => continue,
        };
        let Some(condition) = condition else {
            continue;
        };
        let Some(branch_pc) = last_instruction_pc(cfg, header_pc) else {
            continue;
        };

        eliminated.insert(branch_pc);
        if let Some(def_pc) = condition_def_to_eliminate(
            branch_pc,
            condition,
            lifted,
            dom_tree,
            pc_to_block,
            var_use_count,
        ) {
            eliminated.insert(def_pc);
        }
    }

    eliminated
}

fn condition_def_to_eliminate(
    branch_pc: usize,
    cond: &Condition,
    lifted: Option<&LiftedProgram>,
    dom_tree: &super::DominatorTree,
    pc_to_block: &HashMap<usize, usize>,
    var_use_count: &HashMap<String, usize>,
) -> Option<usize> {
    let lifted = lifted?;

    let (reg, is_zero_test) = match (&cond.lhs, &cond.rhs, &cond.op) {
        (Operand::Reg(reg), Operand::Imm(0), CondOp::Ne | CondOp::Eq) => (*reg, true),
        _ => (0, false),
    };
    if !is_zero_test {
        return None;
    }

    let var_name = lifted.var_at_use.get(&(branch_pc, reg))?;
    let def_pc = *lifted.var_name_to_def_pc.get(var_name)?;
    if !is_safe_condition_def_elimination(
        lifted,
        var_name,
        def_pc,
        branch_pc,
        dom_tree,
        pc_to_block,
        var_use_count,
    ) {
        return None;
    }

    Some(def_pc)
}

fn is_safe_condition_def_elimination(
    lifted: &LiftedProgram,
    var_name: &str,
    def_pc: usize,
    branch_pc: usize,
    dom_tree: &super::DominatorTree,
    pc_to_block: &HashMap<usize, usize>,
    var_use_count: &HashMap<String, usize>,
) -> bool {
    let use_count = var_use_count.get(var_name).copied().unwrap_or(0);
    if use_count != 1 {
        return false;
    }

    let def_block = match pc_to_block.get(&def_pc).copied() {
        Some(pc) => pc,
        None => return false,
    };
    let branch_block = match pc_to_block.get(&branch_pc).copied() {
        Some(pc) => pc,
        None => return false,
    };
    if !dom_tree.dominates(def_block, branch_block) {
        return false;
    }

    lifted.is_synthetic_boolean_temp(var_name, def_pc)
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
    let collapsed = collapse_consecutive_labels(&out);
    let without_redundant_gotos = elide_redundant_gotos(&collapsed);
    let without_unused_labels = prune_unused_labels(&without_redundant_gotos);
    prune_unused_pure_let_definitions(&without_unused_labels)
}

/// Collapse runs of consecutive labels into a single canonical label.
/// Rewrites goto targets to preserve control-flow readability.
fn collapse_consecutive_labels(input: &str) -> String {
    let lines: Vec<String> = input.lines().map(|s| s.to_string()).collect();
    let mut collapsed: Vec<String> = Vec::with_capacity(lines.len());
    let mut aliases: HashMap<String, String> = HashMap::new();

    let mut i = 0usize;
    while i < lines.len() {
        if let Some(canonical_label) = parse_block_label_name(&lines[i]) {
            collapsed.push(lines[i].clone());
            let mut j = i + 1;
            while j < lines.len() {
                if let Some(alias_label) = parse_block_label_name(&lines[j]) {
                    aliases.insert(alias_label, canonical_label.clone());
                    j += 1;
                } else {
                    break;
                }
            }
            i = j;
            continue;
        }

        collapsed.push(lines[i].clone());
        i += 1;
    }

    let mut rewritten: Vec<String> = collapsed;
    if !aliases.is_empty() {
        rewritten = rewritten
            .into_iter()
            .map(|line| apply_aliases(&line, &aliases))
            .collect();
    }

    let mut out = rewritten.join("\n");
    out.push('\n');
    out
}

/// Remove label definitions that are never targeted by any emitted goto.
/// Remove goto statements that jump to the immediately following label.
///
/// Handles two patterns:
///
/// **Pattern 1** – bare goto to next label:
/// ```text
///     goto block_XXXX;
///                           ← optional blank lines
///     block_XXXX:
/// ```
/// The goto line is removed.
///
/// **Pattern 2** – else-only-goto to next label:
/// ```text
///     } else {
///         goto block_XXXX;
///     }
///                           ← optional blank lines
///     block_XXXX:
/// ```
/// The three else lines are replaced with a single `}` to close the if.
fn elide_redundant_gotos(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;

    while i < lines.len() {
        // Try Pattern 2: } else { / goto block_XXXX; / }
        if i + 2 < lines.len() {
            let l0 = lines[i].trim();
            let l1 = lines[i + 1].trim();
            let l2 = lines[i + 2].trim();

            if l0 == "} else {" && l2 == "}" {
                if let Some(goto_label) = parse_goto_target(l1) {
                    // Look ahead past blank lines for matching label
                    let mut j = i + 3;
                    while j < lines.len() && lines[j].trim().is_empty() {
                        j += 1;
                    }
                    if j < lines.len() {
                        if let Some(next_label) = parse_block_label_name(lines[j]) {
                            if goto_label == next_label {
                                // Replace the else block with just `}` to close the if.
                                // The closing brace line (lines[i+2]) already has
                                // the right indentation.
                                kept.push(lines[i + 2]);
                                i += 3;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // Try Pattern 1: goto block_XXXX;
        {
            let trimmed = lines[i].trim();
            if let Some(goto_label) = parse_goto_target(trimmed) {
                let mut j = i + 1;
                while j < lines.len() && lines[j].trim().is_empty() {
                    j += 1;
                }
                if j < lines.len() {
                    if let Some(next_label) = parse_block_label_name(lines[j]) {
                        if goto_label == next_label {
                            // Skip the goto line
                            i += 1;
                            continue;
                        }
                    }
                }
            }
        }

        kept.push(lines[i]);
        i += 1;
    }

    let mut out = kept.join("\n");
    out.push('\n');
    out
}

/// Extract the label name from a `goto block_XXXX;` statement.
fn parse_goto_target(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("goto ")?;
    let rest = rest.strip_suffix(';')?;
    let label = rest.trim();
    if is_block_label_name(label) {
        Some(label.to_string())
    } else {
        None
    }
}

fn prune_unused_labels(input: &str) -> String {
    let referenced = collect_referenced_labels(input);
    let mut kept: Vec<String> = Vec::new();
    let mut prev_blank = false;

    for line in input.lines() {
        if let Some(label) = parse_block_label_name(line)
            && !referenced.contains(&label)
        {
            continue;
        }

        let is_blank = line.trim().is_empty();
        if is_blank {
            if prev_blank || kept.is_empty() {
                continue;
            }
            prev_blank = true;
        } else {
            prev_blank = false;
        }
        kept.push(line.to_string());
    }

    while kept.last().is_some_and(|line| line.trim().is_empty()) {
        kept.pop();
    }

    let mut out = kept.join("\n");
    out.push('\n');
    out
}

fn collect_referenced_labels(input: &str) -> HashSet<String> {
    let mut referenced = HashSet::new();

    for line in input.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find("goto ") {
            let after = &rest[idx + "goto ".len()..];
            let label: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if label.is_empty() {
                break;
            }
            if is_block_label_name(&label) {
                referenced.insert(label.clone());
            }
            rest = &after[label.len()..];
        }
    }

    referenced
}

/// Remove pure local `let` bindings that have no remaining identifier uses.
/// Keeps effectful bindings (e.g. function calls) even when their target is unused.
fn prune_unused_pure_let_definitions(input: &str) -> String {
    let mut lines: Vec<String> = input.lines().map(|s| s.to_string()).collect();
    let has_halt = lines.iter().any(|line| line.trim() == "halt()");
    if !has_halt {
        return input.to_string();
    }
    let func_ids = assign_function_ids(&lines);
    let has_functions = func_ids.iter().any(Option::is_some);
    let halt_func_ids: HashSet<usize> = if has_functions {
        lines
            .iter()
            .enumerate()
            .filter_map(|(idx, line)| {
                if line.trim() == "halt()" {
                    func_ids[idx]
                } else {
                    None
                }
            })
            .collect()
    } else {
        HashSet::new()
    };

    loop {
        let mut uses: HashMap<String, usize> = HashMap::new();

        for line in &lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((_, rhs)) = parse_let_binding(trimmed) {
                for ident in collect_identifiers(rhs) {
                    *uses.entry(ident).or_insert(0) += 1;
                }
            } else {
                for ident in collect_identifiers(trimmed) {
                    *uses.entry(ident).or_insert(0) += 1;
                }
            }
        }

        let mut changed = false;
        let mut kept = Vec::with_capacity(lines.len());
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let remove = if let Some((name, rhs)) = parse_let_binding(trimmed) {
                let in_halt_context = if has_functions {
                    func_ids[idx].is_some_and(|fid| halt_func_ids.contains(&fid))
                } else {
                    true
                };
                in_halt_context && uses.get(name).copied().unwrap_or(0) == 0 && is_pure_let_rhs(rhs)
            } else {
                false
            };
            if remove {
                changed = true;
                continue;
            }
            kept.push(line.clone());
        }

        if !changed {
            break;
        }
        lines = kept;
    }

    let mut compact: Vec<String> = Vec::new();
    let mut prev_blank = false;
    for line in lines {
        let is_blank = line.trim().is_empty();
        if is_blank {
            if prev_blank || compact.is_empty() {
                continue;
            }
            prev_blank = true;
        } else {
            prev_blank = false;
        }
        compact.push(line);
    }
    while compact.last().is_some_and(|line| line.trim().is_empty()) {
        compact.pop();
    }

    let mut out = compact.join("\n");
    out.push('\n');
    out
}

fn assign_function_ids(lines: &[String]) -> Vec<Option<usize>> {
    let mut ids = vec![None; lines.len()];
    let mut current_fn: Option<usize> = None;
    let mut next_fn_id = 0usize;
    let mut depth: isize = 0;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();

        if current_fn.is_none() && trimmed.starts_with("fn ") && trimmed.ends_with('{') {
            current_fn = Some(next_fn_id);
            next_fn_id += 1;
            depth = 1;
            ids[idx] = current_fn;
            continue;
        }

        if let Some(fid) = current_fn {
            ids[idx] = Some(fid);
            depth += count_char(line, '{') as isize;
            depth -= count_char(line, '}') as isize;
            if depth <= 0 {
                current_fn = None;
                depth = 0;
            }
        }
    }

    ids
}

fn count_char(s: &str, needle: char) -> usize {
    s.chars().filter(|&c| c == needle).count()
}

fn parse_let_binding(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("let ")?;
    let name_end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if name_end == 0 {
        return None;
    }
    let name = &rest[..name_end];
    let mut tail = rest[name_end..].trim_start();
    if tail.starts_with(':') {
        if let Some(eq_pos) = tail.find('=') {
            tail = tail[eq_pos + 1..].trim_start();
        } else {
            tail = "";
        }
    } else if tail.starts_with('=') {
        tail = tail[1..].trim_start();
    } else {
        tail = "";
    }
    Some((name, tail))
}

fn collect_identifiers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.push(text[start..i].to_string());
        } else {
            i += 1;
        }
    }
    out
}

fn is_pure_let_rhs(rhs: &str) -> bool {
    !has_probable_call(rhs)
}

fn has_probable_call(expr: &str) -> bool {
    let bytes = expr.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'(' {
            continue;
        }
        let mut j = i;
        while j > 0 && bytes[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        if j == 0 {
            continue;
        }
        if is_ident_byte(bytes[j - 1]) {
            return true;
        }
    }
    false
}

fn parse_block_label_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !(trimmed.starts_with("block_") && trimmed.ends_with(':')) {
        return None;
    }
    let label = &trimmed[..trimmed.len() - 1];
    if !is_block_label_name(label) {
        return None;
    }
    Some(label.to_string())
}

fn is_block_label_name(label: &str) -> bool {
    if !label.starts_with("block_") {
        return false;
    }
    let hex_suffix = &label["block_".len()..];
    !hex_suffix.is_empty() && hex_suffix.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build human-readable labels for blocks that are targets of goto/switch statements.
#[derive(Clone, Debug)]
struct HoistedDecl {
    name: String,
    var_type: Option<String>,
}

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

fn build_block_labels(cfg: &ControlFlowGraph, structures: &[Structure]) -> HashMap<usize, String> {
    let mut labels = HashMap::new();

    // Collect targets that can be rendered as labeled gotos.
    let mut goto_targets: HashSet<usize> = HashSet::new();

    for s in structures {
        if let Structure::Switch { cases, .. } = s {
            for (_, target) in cases {
                if cfg.blocks.contains_key(target) {
                    goto_targets.insert(*target);
                }
            }
        }
    }

    for block in cfg.blocks.values() {
        for (pc, instr) in &block.instructions {
            match instr {
                Instruction::Jump { offset } => {
                    let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, *offset);
                    if cfg.blocks.contains_key(&target) {
                        goto_targets.insert(target);
                    }
                }
                _ => {
                    let shape = InstructionShape::classify(instr);
                    if shape.is_conditional_branch()
                        && let Some(offset) = shape.branch_offset()
                    {
                        let target = crate::cfg::ControlFlowGraph::compute_jump_target(*pc, offset);
                        if cfg.blocks.contains_key(&target) {
                            goto_targets.insert(target);
                        }
                    }
                }
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

fn build_pc_to_block_index(cfg: &ControlFlowGraph) -> HashMap<usize, usize> {
    let mut pc_to_block = HashMap::new();
    for block in cfg.blocks.values() {
        for (pc, _) in &block.instructions {
            pc_to_block.insert(*pc, block.start_pc);
        }
    }
    pc_to_block
}

/// Hoist declarations for variables whose definitions do not dominate all uses.
/// This prevents block-scoped `let` bindings from being used out of scope
/// (e.g., conditionally defined temps referenced after an `if`).
fn collect_hoisted_declarations(
    lifted: &LiftedProgram,
    cfg: &ControlFlowGraph,
) -> Vec<HoistedDecl> {
    let pc_to_block = build_pc_to_block_index(cfg);
    let mut decls = Vec::new();
    let mut seen = HashSet::new();

    let mut definitions: HashMap<String, (usize, Option<String>)> = HashMap::new();
    for (name, def_pc) in &lifted.var_name_to_def_pc {
        let var_type = lifted
            .variables
            .iter()
            .find_map(|(&(pc, _), var)| {
                (pc == *def_pc && var.name == *name).then(|| format!("{}", var.var_type))
            });
        definitions
            .entry(name.clone())
            .or_insert((*def_pc, var_type));
    }
    for (&(pc, _), var) in &lifted.variables {
        definitions
            .entry(var.name.clone())
            .or_insert((pc, Some(format!("{}", var.var_type))));
    }
    for block in cfg.blocks.values() {
        for (pc, instr) in &block.instructions {
            if let Some((_, Some(var_name))) = lifted.format_pc_raw(*pc, instr) {
                definitions.entry(var_name).or_insert((*pc, None));
            }
        }
    }

    for (name, (def_pc, var_type)) in definitions {
        let Some(def_block) = pc_to_block.get(&def_pc).copied() else {
            continue;
        };

        let mut needs_hoist = false;
        for (use_pc, expr) in &lifted.expressions {
            if *use_pc == def_pc {
                continue;
            }
            if !expression_uses_var(expr, &name) {
                continue;
            }
            let Some(use_block) = pc_to_block.get(use_pc).copied() else {
                continue;
            };
            if use_block != def_block {
                needs_hoist = true;
                break;
            }
        }

        if needs_hoist && seen.insert(name.clone()) {
            decls.push(HoistedDecl {
                name: name.clone(),
                var_type: var_type.clone(),
            });
        }
    }

    decls.sort_by(|a, b| a.name.cmp(&b.name));
    decls
}

fn expression_uses_var(expr: &Expression, name: &str) -> bool {
    match expr {
        Expression::Var(n) => n == name,
        Expression::BinOp { lhs, rhs, .. } => {
            expression_uses_var(lhs, name) || expression_uses_var(rhs, name)
        }
        Expression::UnaryOp { operand, .. } => expression_uses_var(operand, name),
        Expression::Load { base, .. } => expression_uses_var(base, name),
        Expression::Store { base, value, .. } => {
            expression_uses_var(base, name) || expression_uses_var(value, name)
        }
        Expression::Call { args, .. } => args.iter().any(|a| expression_uses_var(a, name)),
        Expression::Raw(text) => raw_contains_identifier(text, name),
        Expression::Const(_) => false,
    }
}

fn raw_contains_identifier(raw: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let raw_bytes = raw.as_bytes();
    let needle = name.as_bytes();
    if needle.len() > raw_bytes.len() {
        return false;
    }
    for i in 0..=raw_bytes.len() - needle.len() {
        if &raw_bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_ident_byte(raw_bytes[i - 1]);
            let after_ok = i + needle.len() == raw_bytes.len()
                || !is_ident_byte(raw_bytes[i + needle.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Get the PC of the last instruction in a block (the branch/terminator).
fn last_instruction_pc(cfg: &ControlFlowGraph, block_pc: usize) -> Option<usize> {
    cfg.blocks
        .get(&block_pc)
        .and_then(|b| b.instructions.last())
        .map(|(pc, _)| *pc)
}

/// Format a lifted instruction line using emitter-local declaration tracking.
/// This mirrors `LiftedProgram::format_pc` without mutating `LiftedProgram`.
fn format_pc_with_local_declarations(
    lifted: &LiftedProgram,
    pc: usize,
    instr: &Instruction,
    declared_vars: &mut HashSet<String>,
    var_aliases: &HashMap<String, String>,
) -> Option<String> {
    if lifted.eliminated_pcs.contains(&pc) {
        return None;
    }
    let (raw_line, declare_var) = lifted.format_pc_raw(pc, instr)?;
    let raw_line = recover_folded_addition_assignment(lifted, pc, instr, &raw_line, var_aliases);
    let raw_line = apply_aliases(&raw_line, var_aliases);
    if let Some(var_name) = declare_var
        && {
            let resolved = resolve_alias(&var_name, var_aliases);
            !is_register_name(&resolved) && declared_vars.insert(resolved)
        }
    {
        return Some(format!("let {}", raw_line));
    }
    Some(raw_line)
}

fn recover_folded_addition_assignment(
    lifted: &LiftedProgram,
    pc: usize,
    instr: &Instruction,
    raw_line: &str,
    var_aliases: &HashMap<String, String>,
) -> String {
    let Some(rhs) = recover_folded_addition_rhs(lifted, pc, instr, var_aliases) else {
        return raw_line.to_string();
    };
    let Some(eq_pos) = raw_line.find(" = ") else {
        return raw_line.to_string();
    };
    let lhs = raw_line[..eq_pos].trim_end();
    format!("{} = {}", lhs, rhs)
}

fn recover_folded_addition_rhs(
    lifted: &LiftedProgram,
    pc: usize,
    instr: &Instruction,
    var_aliases: &HashMap<String, String>,
) -> Option<String> {
    use crate::lifting::Expression;

    if !matches!(lifted.expressions.get(&pc), Some(Expression::Const(_))) {
        return None;
    }

    match instr {
        Instruction::Add32 { src1, src2, .. } | Instruction::Add64 { src1, src2, .. } => {
            Some(format!(
                "{} + {}",
                format_add_operand(lifted, pc, *src1, var_aliases),
                format_add_operand(lifted, pc, *src2, var_aliases)
            ))
        }
        _ => None,
    }
}

fn format_add_operand(
    lifted: &LiftedProgram,
    use_pc: usize,
    reg: u8,
    var_aliases: &HashMap<String, String>,
) -> String {
    use crate::lifting::format_expression;

    let ctx = lifted.format_context();
    if let Some(name) = lifted.var_at_use.get(&(use_pc, reg)) {
        if let Some(def_pc) = lifted.var_name_to_def_pc.get(name.as_str())
            && lifted.eliminated_pcs.contains(def_pc)
            && let Some(expr) = lifted.expressions.get(def_pc)
        {
            let resolved = lifted.resolve_eliminated_vars(expr);
            return apply_aliases(&format_expression(&resolved, &ctx), var_aliases);
        }
        return resolve_alias(name, var_aliases);
    }

    format!("r{}", reg)
}

/// Track a register's value after an instruction to make call arguments explicit.
fn register_value_after_instruction(
    lifted: &LiftedProgram,
    pc: usize,
    instr: &Instruction,
    emission_eliminated_pcs: &HashSet<usize>,
    var_aliases: &HashMap<String, String>,
) -> Option<(u8, String)> {
    use crate::lifting::{Expression, format_expression};

    let def_reg = InstructionShape::classify(instr).def_reg()?;
    let ctx = lifted.format_context();

    if (lifted.eliminated_pcs.contains(&pc) || emission_eliminated_pcs.contains(&pc))
        && let Some(expr) = lifted.expressions.get(&pc)
    {
        // Keep register-value tracking coherent even when the defining instruction
        // is folded away from the emitted output.
        if !matches!(expr, Expression::Raw(_) | Expression::Store { .. }) {
            let resolved = lifted.resolve_eliminated_vars(expr);
            let value = apply_aliases(&format_expression(&resolved, &ctx), var_aliases);
            if value == format!("r{}", def_reg) {
                return None;
            }
            return Some((def_reg, value));
        }
    }

    if let Some(var) = lifted.variables.get(&(pc, def_reg)) {
        return Some((def_reg, resolve_alias(&var.name, var_aliases)));
    }

    Some((def_reg, format!("r{}", def_reg)))
}

fn format_named_call(
    lifted: &LiftedProgram,
    callee: &str,
    call_pc: usize,
    block_reg_values: &HashMap<u8, String>,
    var_aliases: &HashMap<String, String>,
    emission_eliminated_pcs: &HashSet<usize>,
) -> String {
    let args = lifted
        .call_param_regs
        .get(callee)
        .map(|regs| {
            regs.iter()
                .map(|&reg| {
                    format_call_arg(
                        lifted,
                        call_pc,
                        reg,
                        block_reg_values,
                        var_aliases,
                        emission_eliminated_pcs,
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    format!("{}({})", callee, args.join(", "))
}

fn format_call_arg(
    lifted: &LiftedProgram,
    call_pc: usize,
    reg: u8,
    block_reg_values: &HashMap<u8, String>,
    var_aliases: &HashMap<String, String>,
    emission_eliminated_pcs: &HashSet<usize>,
) -> String {
    use crate::lifting::format_expression;

    if let Some(value) = block_reg_values.get(&reg) {
        return value.clone();
    }

    let ctx = lifted.format_context();
    if let Some(name) = lifted.var_at_use.get(&(call_pc, reg)) {
        if let Some(def_pc) = lifted.var_name_to_def_pc.get(name.as_str())
            && (lifted.eliminated_pcs.contains(def_pc) || emission_eliminated_pcs.contains(def_pc))
            && let Some(expr) = lifted.expressions.get(def_pc)
        {
            let resolved = lifted.resolve_eliminated_vars(expr);
            return apply_aliases(&format_expression(&resolved, &ctx), var_aliases);
        }
        return resolve_alias(name, var_aliases);
    }

    format!("r{}", reg)
}

fn replace_identifier(input: &str, from: &str, to: &str) -> String {
    if from.is_empty() || from == to {
        return input.to_string();
    }

    let bytes = input.as_bytes();
    let needle = from.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let can_match = i + needle.len() <= bytes.len() && &bytes[i..i + needle.len()] == needle;
        if can_match {
            let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let next_idx = i + needle.len();
            let next_ok = next_idx == bytes.len() || !is_ident_byte(bytes[next_idx]);
            if prev_ok && next_ok {
                out.push_str(to);
                i = next_idx;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_register_name(name: &str) -> bool {
    name.strip_prefix('r')
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
}

fn resolve_alias(name: &str, aliases: &HashMap<String, String>) -> String {
    let mut cur = name;
    let mut guard = 0usize;
    while let Some(next) = aliases.get(cur)
        && next != cur
        && guard < aliases.len()
    {
        cur = next;
        guard += 1;
    }
    cur.to_string()
}

fn apply_aliases(input: &str, aliases: &HashMap<String, String>) -> String {
    if aliases.is_empty() {
        return input.to_string();
    }

    let mut pairs: Vec<(&String, String)> = aliases
        .iter()
        .map(|(from, to)| (from, resolve_alias(to, aliases)))
        .collect();
    pairs.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

    let mut out = input.to_string();
    for (from, to) in pairs {
        if from != &to {
            out = replace_identifier(&out, from, &to);
        }
    }
    out
}

/// Format a condition, using lifted variable names when a lifted program is provided.
fn format_condition_maybe_lifted(
    cond: &Condition,
    cfg: &ControlFlowGraph,
    header_pc: usize,
    lifted: Option<&LiftedProgram>,
    emission_eliminated_pcs: Option<&HashSet<usize>>,
) -> String {
    if let Some(lifted) = lifted
        && let Some(branch_pc) = last_instruction_pc(cfg, header_pc)
    {
        return format_condition_lifted(cond, branch_pc, lifted, emission_eliminated_pcs);
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
        CondOp::LtS => "<s",
        CondOp::LeS => "<=s",
        CondOp::GeS => ">=s",
        CondOp::GtS => ">s",
        CondOp::LeU => "<=u",
        CondOp::GeU => ">=u",
        CondOp::LtU => "<u",
        CondOp::GtU => ">u",
    };
    format!("{} {} {}", lhs, op, rhs)
}

fn maybe_invert_loop_condition(
    cfg: &ControlFlowGraph,
    header_pc: usize,
    loop_body: &HashSet<usize>,
    cond: &Condition,
) -> Condition {
    if should_invert_loop_condition(cfg, header_pc, loop_body) {
        invert_condition(cond)
    } else {
        cond.clone()
    }
}

fn should_invert_loop_condition(
    cfg: &ControlFlowGraph,
    header_pc: usize,
    loop_body: &HashSet<usize>,
) -> bool {
    let Some(header_block) = cfg.blocks.get(&header_pc) else {
        return false;
    };
    let Some((branch_pc, instr)) = header_block.instructions.last() else {
        return false;
    };
    let shape = InstructionShape::classify(instr);
    if !shape.is_conditional_branch() {
        return false;
    }
    let Some(offset) = shape.branch_offset() else {
        return false;
    };
    let branch_target = crate::cfg::ControlFlowGraph::compute_jump_target(*branch_pc, offset);
    let branch_goes_to_body = loop_body.contains(&branch_target);
    let fallthrough_goes_to_body = header_block
        .successors
        .iter()
        .any(|succ| *succ != branch_target && loop_body.contains(succ));
    !branch_goes_to_body && fallthrough_goes_to_body
}

fn invert_condition(cond: &Condition) -> Condition {
    let op = match &cond.op {
        CondOp::Eq => CondOp::Ne,
        CondOp::Ne => CondOp::Eq,
        CondOp::LtS => CondOp::GeS,
        CondOp::LeS => CondOp::GtS,
        CondOp::GeS => CondOp::LtS,
        CondOp::GtS => CondOp::LeS,
        CondOp::LeU => CondOp::GtU,
        CondOp::GeU => CondOp::LtU,
        CondOp::LtU => CondOp::GeU,
        CondOp::GtU => CondOp::LeU,
    };
    Condition {
        op,
        lhs: cond.lhs.clone(),
        rhs: cond.rhs.clone(),
    }
}

/// Format a condition using lifted variable names when available.
/// When the condition is `cond_var != 0` and cond_var was defined by a comparison
/// expression (e.g. `x <u y`), inline the comparison directly.
fn format_condition_lifted(
    cond: &Condition,
    branch_pc: usize,
    lifted: &LiftedProgram,
    emission_eliminated_pcs: Option<&HashSet<usize>>,
) -> String {
    use crate::lifting::format_expression;

    let ctx = lifted.format_context();
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
            // Resolve any eliminated variable references before formatting.
            let resolved = lifted.resolve_eliminated_vars(expr);
            if cond.op == CondOp::Eq {
                // Invert: `cond_var == 0` where cond_var is boolean → negate
                use crate::lifting::simplify_expression;
                let negated = crate::lifting::Expression::UnaryOp {
                    op: crate::instruction::UnaryOp::Not,
                    operand: Box::new(resolved),
                };
                return format_expression(&simplify_expression(negated), &ctx);
            } else {
                return format_expression(&resolved, &ctx);
            }
        }
    }

    let lhs = format_operand_lifted(&cond.lhs, branch_pc, lifted, emission_eliminated_pcs);
    let rhs = format_operand_lifted(&cond.rhs, branch_pc, lifted, emission_eliminated_pcs);
    let op = match cond.op {
        CondOp::Eq => "==",
        CondOp::Ne => "!=",
        CondOp::LtS => "<s",
        CondOp::LeS => "<=s",
        CondOp::GeS => ">=s",
        CondOp::GtS => ">s",
        CondOp::LeU => "<=u",
        CondOp::GeU => ">=u",
        CondOp::LtU => "<u",
        CondOp::GtU => ">u",
    };
    format!("{} {} {}", lhs, op, rhs)
}

fn format_operand(op: &Operand) -> String {
    match op {
        Operand::Reg(r) => format!("r{}", r),
        Operand::Imm(v) => format!("{}", v),
    }
}

fn format_operand_lifted(
    op: &Operand,
    branch_pc: usize,
    lifted: &LiftedProgram,
    emission_eliminated_pcs: Option<&HashSet<usize>>,
) -> String {
    use crate::lifting::format_expression;
    match op {
        Operand::Reg(r) => {
            if let Some(name) = lifted.var_at_use.get(&(branch_pc, *r)) {
                // If the variable was eliminated, inline its definition expression.
                // Skip inlining for variables with multiple uses in var_at_use, since
                // they are likely loop induction variables whose initial constant def
                // was absorbed into a for-loop header but whose name is still live.
                if let Some(def_pc) = lifted.var_name_to_def_pc.get(name.as_str())
                    && (lifted.eliminated_pcs.contains(def_pc)
                        || emission_eliminated_pcs.is_some_and(|s| s.contains(def_pc)))
                    && let Some(expr) = lifted.expressions.get(def_pc)
                {
                    let use_count = lifted
                        .var_at_use
                        .values()
                        .filter(|v| v.as_str() == name.as_str())
                        .count();
                    if use_count <= 1 {
                        let resolved = lifted.resolve_eliminated_vars(expr);
                        return format_expression(&resolved, &lifted.format_context());
                    }
                }
                name.clone()
            } else {
                format!("r{}", r)
            }
        }
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

    fn has_empty_if_or_while(output: &str) -> bool {
        let lines: Vec<&str> = output.lines().collect();
        for i in 0..lines.len().saturating_sub(1) {
            let line = lines[i].trim();
            let next = lines[i + 1].trim();
            if (line.starts_with("if (") || line.starts_with("while ("))
                && line.ends_with('{')
                && next == "}"
            {
                return true;
            }
        }
        false
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
    fn test_loop_exit_branch_inverts_condition_and_elides_forwarder_jump() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Header exits on r1 != 0, while fallthrough enters body via a
        // forwarder block that jumps directly to the latch body.
        let cfg = build_test_cfg(
            0,
            vec![
                (0, vec![(0, Instruction::Jump { offset: 10 })], vec![10]),
                (
                    10,
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 1,
                            value: 0,
                            offset: 20,
                        },
                    )],
                    vec![30, 20],
                ),
                (20, vec![(20, Instruction::Jump { offset: 20 })], vec![40]),
                (
                    40,
                    vec![
                        (
                            40,
                            Instruction::Add32 {
                                dst: 2,
                                src1: 2,
                                src2: 3,
                            },
                        ),
                        (44, Instruction::Jump { offset: -34 }),
                    ],
                    vec![10],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            pseudo.contains("while (r1 == 0)"),
            "Exit-branch loop conditions should be inverted for while rendering: {}",
            pseudo
        );
        assert!(
            !pseudo.contains("goto block_0028;"),
            "Forwarder jumps to the next loop body block should be elided: {}",
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
    fn test_branch_opcode_condition_rendering_paths() {
        let cases = vec![
            (
                Instruction::BranchEqImm {
                    reg: 1,
                    value: 10,
                    offset: 4,
                },
                "r1 == 10",
            ),
            (
                Instruction::BranchNeImm {
                    reg: 2,
                    value: 11,
                    offset: 4,
                },
                "r2 != 11",
            ),
            (
                Instruction::BranchLtSImm {
                    reg: 3,
                    value: 12,
                    offset: 4,
                },
                "r3 <s 12",
            ),
            (
                Instruction::BranchLeSImm {
                    reg: 4,
                    value: 13,
                    offset: 4,
                },
                "r4 <=s 13",
            ),
            (
                Instruction::BranchGeSImm {
                    reg: 5,
                    value: 14,
                    offset: 4,
                },
                "r5 >=s 14",
            ),
            (
                Instruction::BranchGtSImm {
                    reg: 6,
                    value: 15,
                    offset: 4,
                },
                "r6 >s 15",
            ),
            (
                Instruction::BranchLtUImm {
                    reg: 7,
                    value: 16,
                    offset: 4,
                },
                "r7 <u 16",
            ),
            (
                Instruction::BranchLeUImm {
                    reg: 8,
                    value: 17,
                    offset: 4,
                },
                "r8 <=u 17",
            ),
            (
                Instruction::BranchGeUImm {
                    reg: 9,
                    value: 18,
                    offset: 4,
                },
                "r9 >=u 18",
            ),
            (
                Instruction::BranchGtUImm {
                    reg: 10,
                    value: 19,
                    offset: 4,
                },
                "r10 >u 19",
            ),
            (
                Instruction::BranchEq {
                    reg1: 1,
                    reg2: 2,
                    offset: 4,
                },
                "r1 == r2",
            ),
            (
                Instruction::BranchNe {
                    reg1: 2,
                    reg2: 3,
                    offset: 4,
                },
                "r2 != r3",
            ),
            (
                Instruction::BranchLtS {
                    reg1: 3,
                    reg2: 4,
                    offset: 4,
                },
                "r3 <s r4",
            ),
            (
                Instruction::BranchGeS {
                    reg1: 4,
                    reg2: 5,
                    offset: 4,
                },
                "r4 >=s r5",
            ),
            (
                Instruction::BranchLtU {
                    reg1: 5,
                    reg2: 6,
                    offset: 4,
                },
                "r5 <u r6",
            ),
            (
                Instruction::BranchGeU {
                    reg1: 6,
                    reg2: 7,
                    offset: 4,
                },
                "r6 >=u r7",
            ),
        ];

        for (instr, expected) in cases {
            let cond = extract_condition(&instr).expect("branch condition should be extracted");
            let rendered = format_condition(&cond);
            assert_eq!(rendered, expected);
            assert!(
                !rendered.contains("..."),
                "Rendered condition should not contain placeholder"
            );
        }
    }

    #[test]
    fn test_condition_def_elimination_keeps_non_boolean_selector_with_other_uses() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Selector-like value (non-boolean) used in both a branch condition and later computation.
        // Its definition must not be dropped by condition-def elimination.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 1, value: 7 }),
                        (
                            4,
                            Instruction::BranchNeImm {
                                reg: 1,
                                value: 0,
                                offset: 10,
                            },
                        ),
                    ],
                    vec![10, 20],
                ),
                (
                    10,
                    vec![(10, Instruction::LoadImm { reg: 2, value: 1 })],
                    vec![30],
                ),
                (
                    20,
                    vec![(20, Instruction::LoadImm { reg: 2, value: 2 })],
                    vec![30],
                ),
                (
                    30,
                    vec![
                        (
                            30,
                            Instruction::Add32 {
                                dst: 3,
                                src1: 1,
                                src2: 2,
                            },
                        ),
                        (34, Instruction::Trap),
                    ],
                    vec![],
                ),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let selector_name = lifted
            .var_at_use
            .get(&(4, 1))
            .expect("selector should map at branch use")
            .clone();
        let selector_def_pc = *lifted
            .var_name_to_def_pc
            .get(&selector_name)
            .expect("selector should have a def pc");

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let _pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            !lifted.eliminated_pcs.contains(&selector_def_pc),
            "non-boolean selector def must be preserved"
        );
    }

    #[test]
    fn test_hoisting_skips_same_block_definitions() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // var_0 defined and used within the same block — should not be hoisted.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 7 }),
                        (
                            4,
                            Instruction::Add32 {
                                dst: 1,
                                src1: 0,
                                src2: 0,
                            },
                        ),
                    ],
                    vec![],
                ),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let hoisted = collect_hoisted_declarations(&lifted, &cfg);
        assert!(
            hoisted.is_empty(),
            "same-block definition should not be hoisted, but got {:?}",
            hoisted
        );
    }

    #[test]
    fn test_condition_def_elimination_requires_dominating_definition() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Two boolean defs of r1 in different predecessor blocks reach block 30.
        // var_at_use deterministically chooses the smaller def PC (10), but block 10
        // does not dominate block 30. That definition must not be dropped.
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
                        (
                            10,
                            Instruction::SetLtU {
                                dst: 1,
                                src1: 2,
                                src2: 3,
                            },
                        ),
                        (14, Instruction::Jump { offset: 16 }),
                    ],
                    vec![30],
                ),
                (
                    20,
                    vec![
                        (
                            20,
                            Instruction::SetLtU {
                                dst: 1,
                                src1: 4,
                                src2: 5,
                            },
                        ),
                        (24, Instruction::Jump { offset: 6 }),
                    ],
                    vec![30],
                ),
                (
                    30,
                    vec![(
                        30,
                        Instruction::BranchNeImm {
                            reg: 1,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![40, 50],
                ),
                (40, vec![(40, Instruction::Trap)], vec![]),
                (50, vec![(50, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let chosen_name = lifted
            .var_at_use
            .get(&(30, 1))
            .expect("branch condition should use r1")
            .clone();
        let chosen_def_pc = *lifted
            .var_name_to_def_pc
            .get(&chosen_name)
            .expect("chosen condition variable should have a def");
        assert_eq!(chosen_def_pc, 10, "deterministic smallest-def selection");

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let _pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            !lifted.eliminated_pcs.contains(&chosen_def_pc),
            "non-dominating condition def must be preserved"
        );
    }

    #[test]
    fn test_pseudo_code_does_not_mutate_lifted_elimination_set() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Boolean temp in branch condition should be handled by emitter-local
        // suppression state, not by mutating LiftedProgram.eliminated_pcs.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (
                            0,
                            Instruction::SetLtU {
                                dst: 1,
                                src1: 2,
                                src2: 3,
                            },
                        ),
                        (
                            4,
                            Instruction::BranchNeImm {
                                reg: 1,
                                value: 0,
                                offset: 10,
                            },
                        ),
                    ],
                    vec![10, 20],
                ),
                (10, vec![(10, Instruction::Trap)], vec![]),
                (20, vec![(20, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let eliminated_before = lifted.eliminated_pcs.clone();
        let declared_before = lifted.declared_vars.clone();

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let _pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert_eq!(
            lifted.eliminated_pcs, eliminated_before,
            "emitter must not mutate lifted elimination state"
        );
        assert_eq!(
            lifted.declared_vars, declared_before,
            "emitter must not mutate lifted declaration state"
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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
    fn test_for_loop_emission_does_not_mutate_lifted_bindings() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let var_at_use_before = lifted.var_at_use.clone();
        let def_index_before = lifted.var_name_to_def_pc.clone();

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            pseudo.contains("for ("),
            "Expected for-loop output for binding-stability check: {}",
            pseudo
        );
        assert_eq!(
            lifted.var_at_use, var_at_use_before,
            "emitter must not mutate lifted use-site bindings"
        );
        assert_eq!(
            lifted.var_name_to_def_pc, def_index_before,
            "emitter must not mutate lifted def index"
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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

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
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), Some(&sig));

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);

        let sig = FunctionSignature {
            name: "loopy".to_string(),
            params: vec![],
        };

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), Some(&sig));

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            pseudo.contains("helper_func()"),
            "Should render Jump to known function as call: {}",
            pseudo
        );
    }

    #[test]
    fn test_call_target_renders_explicit_arguments_from_register_state() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 1, value: 100 }),
                        (4, Instruction::LoadImm { reg: 7, value: 17 }),
                        (8, Instruction::LoadImm { reg: 0, value: 1 }),
                        (12, Instruction::Jump { offset: 0x100 - 12 }),
                    ],
                    vec![20],
                ),
                (20, vec![(20, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let mut lifted = LiftedProgram::analyze(&cfg, &dataflow);
        lifted.call_targets.insert(0x100, "helper_func".to_string());
        lifted
            .call_param_regs
            .insert("helper_func".to_string(), vec![1, 7]);

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        let call_line = pseudo
            .lines()
            .find(|line| line.contains("helper_func("))
            .expect("helper_func call should be present");
        assert!(
            call_line.contains(','),
            "Call should render both arguments explicitly: {}",
            pseudo
        );
        assert!(
            !call_line.contains("helper_func()"),
            "Call should not be rendered as zero-arg when signature is known: {}",
            pseudo
        );
    }

    #[test]
    fn test_unresolved_direct_jump_renders_labeled_goto() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Target block has two predecessors, so it cannot be linearized as
        // simple fallthrough and must keep explicit goto form.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 1 }),
                        (4, Instruction::Jump { offset: 20 }),
                    ],
                    vec![24],
                ),
                (10, vec![(10, Instruction::Jump { offset: 14 })], vec![24]),
                (24, vec![(24, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        // When the only goto to block_0018 falls through to it, the
        // redundant-goto pass elides it and the label becomes unused.
        assert!(
            !pseudo.contains("goto block_0018;"),
            "Fallthrough goto should be elided: {}",
            pseudo
        );
        assert!(
            !pseudo.contains("block_0018:"),
            "Label with no remaining goto references should be pruned: {}",
            pseudo
        );
    }

    #[test]
    fn test_linear_successor_jump_is_rendered_as_fallthrough() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![
                        (0, Instruction::LoadImm { reg: 0, value: 1 }),
                        (4, Instruction::Jump { offset: 6 }),
                    ],
                    vec![10],
                ),
                (10, vec![(10, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            !pseudo.contains("goto block_000a;"),
            "Linear jump to immediate successor should be rendered as fallthrough: {}",
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
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            pseudo.contains("target_func()"),
            "Should render JumpInd to known function as call: {}",
            pseudo
        );
    }

    #[test]
    fn test_unresolved_indirect_call_rendering_is_explicit_and_stable() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![
                    (
                        0,
                        Instruction::LoadImm {
                            reg: 3,
                            value: 0x1234,
                        },
                    ),
                    (4, Instruction::JumpInd { reg: 3, offset: 0 }),
                ],
                vec![],
            )],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());

        let lifted_a = LiftedProgram::analyze(&cfg, &dataflow);
        let pseudo_a = result.pseudo_code(&cfg, Some(&lifted_a), None);

        let lifted_b = LiftedProgram::analyze(&cfg, &dataflow);
        let pseudo_b = result.pseudo_code(&cfg, Some(&lifted_b), None);

        assert_eq!(
            pseudo_a, pseudo_b,
            "Unresolved indirect-call rendering must be deterministic"
        );
        assert!(
            pseudo_a.contains("call_indirect("),
            "Unknown JumpInd target should render explicitly as indirect call: {}",
            pseudo_a
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
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

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
    fn test_omit_hollow_if_shell() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Header branches to a no-op then block and a trap else block.
        // In lifted mode this used to produce an empty `if {}` shell.
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
                (10, vec![(10, Instruction::Fallthrough)], vec![30]),
                (20, vec![(20, Instruction::Trap)], vec![]),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            !has_empty_if_or_while(&pseudo),
            "Should not emit hollow if/while shells: {}",
            pseudo
        );
    }

    #[test]
    fn test_omit_hollow_while_shell() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;

        // Loop with an empty latch/body should not render as `while (...) {}`.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(
                        0,
                        Instruction::BranchNeImm {
                            reg: 1,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![10, 20],
                ),
                (10, vec![(10, Instruction::Jump { offset: -10 })], vec![0]),
                (20, vec![(20, Instruction::Trap)], vec![]),
            ],
        );

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            !has_empty_if_or_while(&pseudo),
            "Should not emit hollow if/while shells: {}",
            pseudo
        );
    }

    #[test]
    fn test_conditional_branch_goto_rendering() {
        // Verify that real binary output never renders raw jump offsets in
        // pseudo-code. Unstructured branches may render as goto labels, but
        // fully structured output can legitimately contain no gotos.
        let bytes = std::fs::read("examples/compiled/as-fibonacci.pvm")
            .expect("as-fibonacci.pvm fixture required");
        let output =
            crate::decompile_bytes(&bytes).expect("as-fibonacci should decompile successfully");

        // No raw jump offsets should remain
        assert!(
            !output.contains("jump "),
            "Should not contain raw jump offsets: {}",
            output
        );
        // If any goto is emitted, it should target named labels.
        if output.contains("goto ") {
            assert!(
                output.contains("goto block_"),
                "Goto targets should use labels, not raw offsets: {}",
                output
            );
        }
    }

    #[test]
    fn test_dispatch_switch_renders_as_loop_switch() {
        use crate::dataflow::DataFlowAnalysis;
        use crate::lifting::LiftedProgram;
        use std::collections::HashSet;

        // Dispatch-like CFG:
        //   0: JumpInd switch -> case targets 4 and 8
        //   4: case body then Jump back to 0 (should render as `continue`)
        //   8: conditional branch to 12, fallthrough back to 0
        //  12: exit trap
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::JumpInd { reg: 3, offset: 0 })],
                    vec![4, 8],
                ),
                (
                    4,
                    vec![
                        (4, Instruction::LoadImm { reg: 1, value: 7 }),
                        (6, Instruction::Jump { offset: -6 }),
                    ],
                    vec![0],
                ),
                (
                    8,
                    vec![(
                        8,
                        Instruction::BranchNeImm {
                            reg: 2,
                            value: 0,
                            offset: 4,
                        },
                    )],
                    vec![12, 0],
                ),
                (12, vec![(12, Instruction::Trap)], vec![]),
            ],
        );
        let program = DecodedProgram {
            jump_table: vec![4, 8],
            instructions: vec![(0, Instruction::JumpInd { reg: 3, offset: 0 })],
            memory_base: None,
            code_len: 13,
        };
        let dom_tree = crate::structuring::DominatorTree::compute(&cfg);
        let function_entry_pcs: HashSet<usize> = [0].into_iter().collect();
        let result =
            StructuralAnalysis::analyze_with_dom_tree(&cfg, &program, dom_tree, function_entry_pcs);

        let dataflow = DataFlowAnalysis::analyze(&cfg);
        let lifted = LiftedProgram::analyze(&cfg, &dataflow);
        let pseudo = result.pseudo_code(&cfg, Some(&lifted), None);

        assert!(
            pseudo.contains("loop {"),
            "Dispatch switch should render as loop: {}",
            pseudo
        );
        assert!(
            pseudo.contains("switch ("),
            "Dispatch loop should include switch: {}",
            pseudo
        );
        assert!(
            pseudo.contains("case 0: goto block_0004;"),
            "Dispatch case 0 should target block_0004: {}",
            pseudo
        );
        assert!(
            pseudo.contains("case 1: goto block_0008;"),
            "Dispatch case 1 should target block_0008: {}",
            pseudo
        );
        assert!(
            pseudo.contains("continue"),
            "Back-edge to dispatch header should render as continue: {}",
            pseudo
        );
    }

    #[test]
    fn test_collapse_consecutive_labels_rewrites_gotos_to_canonical_label() {
        let input = "\
block_0001:
block_0002:
block_0003:
goto block_0002;
case 4: goto block_0003;
";

        let output = fix_blank_lines(input);

        assert!(
            output.contains("block_0001:"),
            "Canonical label should remain: {}",
            output
        );
        assert!(
            !output.contains("block_0002:"),
            "Alias labels should be collapsed: {}",
            output
        );
        assert!(
            !output.contains("block_0003:"),
            "Alias labels should be collapsed: {}",
            output
        );
        assert!(
            output.contains("goto block_0001;"),
            "Goto targets should be rewritten to canonical label: {}",
            output
        );
    }

    #[test]
    fn test_prune_unused_labels_keeps_only_referenced_targets() {
        let input = "\
block_0001:
let var_0 = 1
goto block_0003;
block_0003:
return
";

        let output = fix_blank_lines(input);

        assert!(
            !output.contains("block_0001:"),
            "Unused labels should be removed: {}",
            output
        );
        // The goto to block_0003 is elided (it falls through), so
        // block_0003 becomes unreferenced and is also pruned.
        assert!(
            !output.contains("goto block_0003;"),
            "Redundant goto to next label should be elided: {}",
            output
        );
        assert!(
            !output.contains("block_0003:"),
            "Label with no remaining references should be pruned: {}",
            output
        );
    }

    #[test]
    fn test_prune_unused_pure_let_definitions_keeps_effectful_bindings() {
        let input = "\
let ptr_0_64 = 17179869184
let var_1 = 1
let var_2 = sbrk(var_1)
halt()
";

        let output = fix_blank_lines(input);

        assert!(
            !output.contains("let ptr_0_64 = 17179869184"),
            "Unused pure let should be removed: {}",
            output
        );
        assert!(
            output.contains("let var_2 = sbrk(var_1)"),
            "Effectful let bindings must be preserved even if unused: {}",
            output
        );
    }
}
