//! Structural Analysis - Recover High-Level Control Structures from CFG
//!
//! Detects loops, if-then-else, and switch/case patterns from the control flow
//! graph and produces pseudo-code output for human-readable disassembly.

use crate::cfg::ControlFlowGraph;
use crate::decoder::DecodedProgram;
use crate::instruction::InstructionShape;
use crate::lifting::LiftedProgram;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use wasm_pvm::pvm::Instruction;

/// Function signature information for pseudo-code emission.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// Function name (e.g., "func_0", "main").
    pub name: String,
    /// Parameter register numbers, sorted.
    pub params: Vec<u8>,
}

/// A recovered high-level control structure.
#[derive(Debug, Clone)]
pub enum Structure {
    /// A natural loop: header block dominates latch, latch has back-edge to header.
    Loop {
        header: usize,
        latch: usize,
        body: HashSet<usize>,
        condition: Option<Condition>,
    },
    /// An if-then-else (diamond) or if-then (triangle) pattern.
    IfThenElse {
        header: usize,
        then_blocks: Vec<usize>,
        else_blocks: Vec<usize>, // empty for if-then (triangle)
        join: Option<usize>,
        condition: Option<Condition>,
    },
    /// A switch/case via indirect jump table.
    Switch {
        header: usize,
        reg: u8,
        cases: Vec<(Vec<u32>, usize)>, // (case values, target block PC)
    },
}

/// A branch condition extracted from a terminator instruction.
#[derive(Debug, Clone)]
pub struct Condition {
    pub op: CondOp,
    pub lhs: Operand,
    pub rhs: Operand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondOp {
    Eq,
    Ne,
    GeS,
    GeU,
    LtU,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Reg(u8),
    Imm(i32),
}

/// Dominator tree computed using the Cooper-Harvey-Kennedy iterative algorithm.
#[derive(Debug)]
#[allow(dead_code)]
pub struct DominatorTree {
    /// Immediate dominator for each block (block PC -> idom PC).
    pub idom: HashMap<usize, usize>,
    /// Children in the dominator tree (block PC -> children PCs).
    pub children: HashMap<usize, Vec<usize>>,
    /// Reverse post-order of block PCs.
    pub rpo: Vec<usize>,
    /// RPO index for each block (block PC -> index).
    rpo_index: HashMap<usize, usize>,
    entry: usize,
}

impl DominatorTree {
    /// Compute the dominator tree for a CFG using the iterative algorithm.
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let rpo = Self::compute_rpo(cfg);
        let rpo_index: HashMap<usize, usize> =
            rpo.iter().enumerate().map(|(i, &pc)| (pc, i)).collect();

        let entry = cfg.entry_pc;
        let mut idom: HashMap<usize, usize> = HashMap::new();
        idom.insert(entry, entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry {
                    continue;
                }
                let block = match cfg.blocks.get(&b) {
                    Some(block) => block,
                    None => continue,
                };

                // Find first processed predecessor
                let mut new_idom = None;
                for &p in &block.predecessors {
                    if idom.contains_key(&p) {
                        new_idom = Some(p);
                        break;
                    }
                }

                let mut new_idom = match new_idom {
                    Some(n) => n,
                    None => continue,
                };

                // Intersect with remaining processed predecessors
                for &p in &block.predecessors {
                    if p == new_idom {
                        continue;
                    }
                    if idom.contains_key(&p) {
                        new_idom = Self::intersect(p, new_idom, &idom, &rpo_index);
                    }
                }

                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        // Build children map
        let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
        for (&node, &dom) in &idom {
            if node != dom {
                children.entry(dom).or_default().push(node);
            }
        }
        // Sort children for deterministic output
        for v in children.values_mut() {
            v.sort();
        }

        DominatorTree {
            idom,
            children,
            rpo,
            rpo_index,
            entry,
        }
    }

    /// Does block `a` dominate block `b`?
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        loop {
            match self.idom.get(&cur) {
                Some(&dom) if dom == cur => return false, // reached entry without finding a
                Some(&dom) if dom == a => return true,
                Some(&dom) => cur = dom,
                None => return false,
            }
        }
    }

    /// Intersect two nodes in the dominator tree (find common dominator).
    fn intersect(
        mut b1: usize,
        mut b2: usize,
        idom: &HashMap<usize, usize>,
        rpo_index: &HashMap<usize, usize>,
    ) -> usize {
        while b1 != b2 {
            let i1 = rpo_index.get(&b1).copied().unwrap_or(usize::MAX);
            let i2 = rpo_index.get(&b2).copied().unwrap_or(usize::MAX);
            if i1 > i2 {
                b1 = *idom.get(&b1).unwrap_or(&b1);
            } else {
                b2 = *idom.get(&b2).unwrap_or(&b2);
            }
        }
        b1
    }

    /// Compute reverse post-order traversal from the entry block.
    fn compute_rpo(cfg: &ControlFlowGraph) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();

        Self::dfs_post_order(cfg, cfg.entry_pc, &mut visited, &mut post_order);

        post_order.reverse();
        post_order
    }

    fn dfs_post_order(
        cfg: &ControlFlowGraph,
        node: usize,
        visited: &mut HashSet<usize>,
        post_order: &mut Vec<usize>,
    ) {
        if !visited.insert(node) {
            return;
        }
        let Some(block) = cfg.blocks.get(&node) else {
            return;
        };
        for &succ in &block.successors {
            Self::dfs_post_order(cfg, succ, visited, post_order);
        }
        post_order.push(node);
    }
}

/// Result of structural analysis.
#[derive(Debug)]
pub struct StructuralAnalysis {
    pub structures: Vec<Structure>,
    pub dom_tree: DominatorTree,
}

impl StructuralAnalysis {
    /// Run structural analysis on a CFG.
    /// Convenience method that computes its own dominator tree.
    /// Use `analyze_with_dom_tree` when sharing a pre-computed tree.
    #[cfg(test)]
    pub fn analyze(cfg: &ControlFlowGraph, program: &DecodedProgram) -> Self {
        let dom_tree = DominatorTree::compute(cfg);
        Self::analyze_with_dom_tree(cfg, program, dom_tree)
    }

    /// Run structural analysis reusing a pre-computed dominator tree.
    pub fn analyze_with_dom_tree(
        cfg: &ControlFlowGraph,
        program: &DecodedProgram,
        dom_tree: DominatorTree,
    ) -> Self {
        if cfg.blocks.is_empty() {
            return StructuralAnalysis {
                structures: Vec::new(),
                dom_tree,
            };
        }
        let mut structures = Vec::new();

        // Detect loops (back-edges where target dominates source)
        let loops = Self::detect_loops(cfg, &dom_tree);
        structures.extend(loops);

        // Collect loop headers for exclusion in if-then-else detection
        let loop_headers: HashSet<usize> = structures
            .iter()
            .filter_map(|s| match s {
                Structure::Loop { header, .. } => Some(*header),
                _ => None,
            })
            .collect();

        // Detect if-then-else patterns
        let ifs = Self::detect_if_then_else(cfg, &dom_tree, &loop_headers);
        structures.extend(ifs);

        // Detect switch/case patterns
        let switches = Self::detect_switches(cfg, program);
        structures.extend(switches);

        StructuralAnalysis {
            structures,
            dom_tree,
        }
    }

    /// Detect natural loops by finding back-edges.
    fn detect_loops(cfg: &ControlFlowGraph, dom_tree: &DominatorTree) -> Vec<Structure> {
        let mut loops = Vec::new();

        for block in cfg.blocks.values() {
            for &succ in &block.successors {
                // A back-edge is B -> A where A dominates B
                if dom_tree.dominates(succ, block.start_pc) && succ != block.start_pc
                    || (succ == block.start_pc && block.predecessors.contains(&block.start_pc))
                {
                    // Self-loop or back-edge found
                    let header = succ;
                    let latch = block.start_pc;

                    // Collect loop body via predecessor walk from latch to header
                    let body = Self::collect_loop_body(cfg, header, latch);

                    // Extract condition from header's terminator
                    let condition = cfg
                        .blocks
                        .get(&header)
                        .and_then(|b| b.instructions.last())
                        .and_then(|(_, instr)| extract_condition(instr));

                    loops.push(Structure::Loop {
                        header,
                        latch,
                        body,
                        condition,
                    });
                }
            }
        }

        // Sort by header PC for deterministic output
        loops.sort_by_key(|l| match l {
            Structure::Loop { header, .. } => *header,
            _ => 0,
        });
        loops
    }

    /// Collect loop body blocks by walking predecessors from latch to header.
    fn collect_loop_body(cfg: &ControlFlowGraph, header: usize, latch: usize) -> HashSet<usize> {
        let mut body = HashSet::new();
        body.insert(header);
        if header == latch {
            return body;
        }

        let mut stack = vec![latch];
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
        body
    }

    /// Detect if-then-else (diamond) and if-then (triangle) patterns.
    fn detect_if_then_else(
        cfg: &ControlFlowGraph,
        dom_tree: &DominatorTree,
        loop_headers: &HashSet<usize>,
    ) -> Vec<Structure> {
        let mut ifs = Vec::new();

        for &block_pc in &dom_tree.rpo {
            let block = match cfg.blocks.get(&block_pc) {
                Some(b) => b,
                None => continue,
            };

            // Only consider 2-successor blocks that aren't loop headers
            if block.successors.len() != 2 || loop_headers.contains(&block_pc) {
                continue;
            }

            let then_entry = block.successors[0];
            let else_entry = block.successors[1];

            // Check for back-edges (skip if either successor is a back-edge target)
            if dom_tree.dominates(then_entry, block_pc) || dom_tree.dominates(else_entry, block_pc)
            {
                continue;
            }

            // Find join point by forward walk from both successors
            let join = Self::find_join_point(cfg, then_entry, else_entry, block_pc, dom_tree);

            // Classify: triangle (one branch IS the join) or diamond
            let (then_blocks, else_blocks) = if Some(then_entry) == join {
                // else-then triangle: "then" branch goes directly to join
                (vec![], vec![else_entry])
            } else if Some(else_entry) == join {
                // if-then triangle: "else" branch goes directly to join
                (vec![then_entry], vec![])
            } else {
                // Diamond or complex
                (vec![then_entry], vec![else_entry])
            };

            let condition = block
                .instructions
                .last()
                .and_then(|(_, instr)| extract_condition(instr));

            ifs.push(Structure::IfThenElse {
                header: block_pc,
                then_blocks,
                else_blocks,
                join,
                condition,
            });
        }

        ifs
    }

    /// Find the nearest common join block reachable from both successors.
    fn find_join_point(
        cfg: &ControlFlowGraph,
        succ_a: usize,
        succ_b: usize,
        header: usize,
        dom_tree: &DominatorTree,
    ) -> Option<usize> {
        // Walk forward from succ_a collecting reachable blocks
        let reachable_a = Self::forward_reachable(cfg, succ_a, header, 20);

        // Walk forward from succ_b and find first block also reachable from a
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(succ_b);

        while let Some(node) = queue.pop_front() {
            if !visited.insert(node) {
                continue;
            }
            if reachable_a.contains(&node) && node != succ_a {
                return Some(node);
            }
            if let Some(block) = cfg.blocks.get(&node) {
                for &s in &block.successors {
                    if !visited.contains(&s) && !dom_tree.dominates(s, header) {
                        queue.push_back(s);
                    }
                }
            }
        }

        // Also check if succ_a or succ_b directly IS the join
        if reachable_a.contains(&succ_b) {
            return Some(succ_b);
        }

        None
    }

    /// Collect blocks reachable in a forward walk from `start`, stopping at back-edges
    /// to `stop` and limiting depth.
    fn forward_reachable(
        cfg: &ControlFlowGraph,
        start: usize,
        stop: usize,
        max_depth: usize,
    ) -> HashSet<usize> {
        let mut reachable = HashSet::new();
        let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
        queue.push_back((start, 0));
        reachable.insert(start);

        while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(block) = cfg.blocks.get(&node) {
                for &s in &block.successors {
                    if s != stop && reachable.insert(s) {
                        queue.push_back((s, depth + 1));
                    }
                }
            }
        }
        reachable
    }

    /// Detect switch/case patterns from indirect jumps with jump tables.
    fn detect_switches(cfg: &ControlFlowGraph, program: &DecodedProgram) -> Vec<Structure> {
        let mut switches = Vec::new();

        for block in cfg.blocks.values() {
            if let Some((_, Instruction::JumpInd { reg, .. })) = block.instructions.last() {
                if program.jump_table.is_empty() {
                    continue;
                }

                // Group jump table entries by target
                let mut target_cases: HashMap<u32, Vec<u32>> = HashMap::new();
                for (idx, &target) in program.jump_table.iter().enumerate() {
                    target_cases.entry(target).or_default().push(idx as u32);
                }

                let mut cases: Vec<(Vec<u32>, usize)> = target_cases
                    .into_iter()
                    .map(|(target, values)| (values, target as usize))
                    .collect();
                cases.sort_by_key(|(_, target)| *target);

                switches.push(Structure::Switch {
                    header: block.start_pc,
                    reg: *reg,
                    cases,
                });
            }
        }

        switches
    }

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
                Structure::Switch { header, reg, cases } => {
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
                Structure::Switch { header, .. } => {
                    switch_map.insert(*header, s);
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
            }) = loop_map.get(&block_pc)
            {
                em.emit_loop(block_pc, body, *latch, condition);
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
            }
            self.emitted.insert(tb);
        }

        if !else_blocks.is_empty() {
            let _ = writeln!(self.output, "{}}} else {{", prefix);
            for &eb in else_blocks {
                let ctrl = self.emit_block_with_loop_control(eb, indent + 1, loop_context);
                if let Some(keyword) = ctrl {
                    let _ = writeln!(self.output, "{}{}", inner_prefix, keyword);
                }
                self.emitted.insert(eb);
            }
        }

        let _ = writeln!(self.output, "{}}}", prefix);
        self.emitted.insert(header);
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
                    // Skip noise instructions in lifted mode.
                    if matches!(instr, Instruction::Fallthrough | Instruction::Jump { .. }) {
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
    ) {
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
                "for ({}; {}; {}) {{",
                info.init_str, cond_str, info.step_str
            );
        } else {
            let _ = writeln!(self.output, "while ({}) {{", cond_str);
        }

        // Emit header block body (before the condition branch)
        self.emit_block_body(header_pc, 1, true);

        let mut body_sorted: Vec<usize> = body.iter().copied().collect();
        body_sorted.sort();
        for &body_pc in &body_sorted {
            if body_pc == header_pc || self.emitted.contains(&body_pc) {
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
                    1,
                    Some((body, header_pc)),
                );
                continue;
            }

            if is_latch {
                self.emit_block_body(body_pc, 1, true);
            } else {
                let ctrl = self.emit_block_with_loop_control(body_pc, 1, Some((body, header_pc)));
                if let Some(keyword) = ctrl {
                    let _ = writeln!(self.output, "    {}", keyword);
                }
            }
            self.emitted.insert(body_pc);
        }

        self.output.push_str("}\n");
        self.emitted.extend(body.iter());
    }

    /// Emit a switch/case structure.
    fn emit_switch(&mut self, block_pc: usize, reg: u8, cases: &[(Vec<u32>, usize)]) {
        self.emit_block_body(block_pc, 0, true);

        let switch_var = if let Some(ref mut lifted) = self.lifted {
            if let Some(branch_pc) = last_instruction_pc(self.cfg, block_pc) {
                if let Some(name) = lifted.var_at_use.get(&(branch_pc, reg)).cloned() {
                    if lifted.declared_vars.insert(name.clone()) {
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

    let mut out = final_lines.join("\n");
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
        break; // Only check the last meaningful instruction
    }

    let (init_str, init_pc) = init_result?;

    // Find the step: the last non-eliminated instruction in the latch block
    // that defines cond_reg (e.g., i = i + 1)
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
        break;
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
        if let Structure::Switch { cases, .. } = s {
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

/// Extract a branch condition from a terminator instruction.
fn extract_condition(instr: &Instruction) -> Option<Condition> {
    match instr {
        Instruction::BranchEqImm { reg, value, .. } => Some(Condition {
            op: CondOp::Eq,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchNeImm { reg, value, .. } => Some(Condition {
            op: CondOp::Ne,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGeSImm { reg, value, .. } => Some(Condition {
            op: CondOp::GeS,
            lhs: Operand::Reg(*reg),
            rhs: Operand::Imm(*value),
        }),
        Instruction::BranchGeU { reg1, reg2, .. } => Some(Condition {
            op: CondOp::GeU,
            lhs: Operand::Reg(*reg1),
            rhs: Operand::Reg(*reg2),
        }),
        Instruction::BranchLtU { reg1, reg2, .. } => Some(Condition {
            op: CondOp::LtU,
            lhs: Operand::Reg(*reg1),
            rhs: Operand::Reg(*reg2),
        }),
        _ => None,
    }
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
    use crate::instruction::BinOp;
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
        // Check if the expression is a comparison (LtU, LtS)
        if let crate::lifting::Expression::BinOp { op, .. } = expr
            && matches!(op, BinOp::LtU | BinOp::LtS)
        {
            let inner = format_expression(expr);
            return if cond.op == CondOp::Eq {
                format!("!({})", inner)
            } else {
                inner
            };
        }
        // Check if it's a negation: !bool
        if let crate::lifting::Expression::UnaryOp {
            op: crate::instruction::UnaryOp::Not,
            operand,
        } = expr
        {
            return if cond.op == CondOp::Eq {
                format_expression(operand)
            } else {
                format_expression(expr)
            };
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

    fn empty_program() -> DecodedProgram {
        DecodedProgram {
            jump_table: vec![],
            instructions: vec![],
            code_len: 0,
        }
    }

    // --- Dominator tree tests ---

    #[test]
    fn test_dominator_tree_linear() {
        // A -> B -> C
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
                    vec![(10, Instruction::LoadImm { reg: 1, value: 2 })],
                    vec![20],
                ),
                (20, vec![(20, Instruction::Trap)], vec![]),
            ],
        );

        let dom = DominatorTree::compute(&cfg);

        assert!(dom.dominates(0, 0));
        assert!(dom.dominates(0, 10));
        assert!(dom.dominates(0, 20));
        assert!(dom.dominates(10, 20));
        assert!(!dom.dominates(20, 10));
        assert!(!dom.dominates(10, 0));
    }

    #[test]
    fn test_dominator_tree_diamond() {
        //     0
        //    / \
        //  10   20
        //    \ /
        //     30
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
                    vec![(10, Instruction::LoadImm { reg: 1, value: 1 })],
                    vec![30],
                ),
                (
                    20,
                    vec![(20, Instruction::LoadImm { reg: 1, value: 2 })],
                    vec![30],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dom = DominatorTree::compute(&cfg);

        assert!(dom.dominates(0, 10));
        assert!(dom.dominates(0, 20));
        assert!(dom.dominates(0, 30));
        // Neither 10 nor 20 dominates 30 (both paths reach 30)
        assert!(!dom.dominates(10, 30));
        assert!(!dom.dominates(20, 30));
    }

    #[test]
    fn test_dominator_tree_with_loop() {
        // 0 -> 10 -> 20 -> 10 (back-edge)
        //             |
        //             v
        //            30
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
                (20, vec![(20, Instruction::Jump { offset: -10 })], vec![10]),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let dom = DominatorTree::compute(&cfg);

        assert!(dom.dominates(0, 10));
        assert!(dom.dominates(10, 20));
        assert!(dom.dominates(10, 30));
        // 20 does NOT dominate 10 (10 is reachable from 0 without going through 20)
        assert!(!dom.dominates(20, 10));
    }

    // --- Loop detection tests ---

    #[test]
    fn test_simple_loop_detection() {
        // 0 -> 10 -> 20 -> 10 (back-edge)
        //       |
        //       v
        //      30
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
                (20, vec![(20, Instruction::Jump { offset: -10 })], vec![10]),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());

        let loops: Vec<&Structure> = result
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::Loop { .. }))
            .collect();
        assert_eq!(loops.len(), 1);

        if let Structure::Loop {
            header,
            latch,
            body,
            ..
        } = loops[0]
        {
            assert_eq!(*header, 10);
            assert_eq!(*latch, 20);
            assert!(body.contains(&10));
            assert!(body.contains(&20));
            assert!(!body.contains(&0));
            assert!(!body.contains(&30));
        } else {
            panic!("Expected Loop");
        }
    }

    #[test]
    fn test_nested_loops() {
        // 0 -> 10 -> 20 -> 30 -> 20 (inner back-edge)
        //       ^              |
        //       |              v
        //       +---- 40 <----+
        //             (outer back-edge: 40 -> 10)
        //       |
        //       v
        //      50
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
                    vec![(
                        10,
                        Instruction::BranchNeImm {
                            reg: 0,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![20, 50],
                ),
                (
                    20,
                    vec![(
                        20,
                        Instruction::BranchNeImm {
                            reg: 1,
                            value: 0,
                            offset: 10,
                        },
                    )],
                    vec![30, 40],
                ),
                (30, vec![(30, Instruction::Jump { offset: -10 })], vec![20]),
                (40, vec![(40, Instruction::Jump { offset: -30 })], vec![10]),
                (50, vec![(50, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());

        let loops: Vec<&Structure> = result
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::Loop { .. }))
            .collect();
        assert_eq!(loops.len(), 2);

        // Inner loop: header=20, latch=30
        let inner = loops
            .iter()
            .find(|l| matches!(l, Structure::Loop { header: 20, .. }));
        assert!(inner.is_some(), "Inner loop at header=20 not found");

        // Outer loop: header=10, latch=40
        let outer = loops
            .iter()
            .find(|l| matches!(l, Structure::Loop { header: 10, .. }));
        assert!(outer.is_some(), "Outer loop at header=10 not found");
    }

    // --- If-then-else tests ---

    #[test]
    fn test_if_then_else_diamond() {
        //     0
        //    / \
        //  10   20
        //    \ /
        //     30
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
                    vec![(10, Instruction::LoadImm { reg: 1, value: 1 })],
                    vec![30],
                ),
                (
                    20,
                    vec![(20, Instruction::LoadImm { reg: 1, value: 2 })],
                    vec![30],
                ),
                (30, vec![(30, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());

        let ifs: Vec<&Structure> = result
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::IfThenElse { .. }))
            .collect();
        assert_eq!(ifs.len(), 1);

        if let Structure::IfThenElse {
            header,
            then_blocks,
            else_blocks,
            join,
            condition,
        } = ifs[0]
        {
            assert_eq!(*header, 0);
            assert_eq!(then_blocks, &[10]);
            assert_eq!(else_blocks, &[20]);
            assert_eq!(*join, Some(30));
            assert!(condition.is_some());
        } else {
            panic!("Expected IfThenElse");
        }
    }

    #[test]
    fn test_if_then_triangle() {
        //     0
        //    / \
        //  10   |
        //    \ /
        //     20
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
                    vec![(10, Instruction::LoadImm { reg: 1, value: 1 })],
                    vec![20],
                ),
                (20, vec![(20, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());

        let ifs: Vec<&Structure> = result
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::IfThenElse { .. }))
            .collect();
        assert_eq!(ifs.len(), 1);

        if let Structure::IfThenElse {
            then_blocks,
            else_blocks,
            join,
            ..
        } = ifs[0]
        {
            assert_eq!(then_blocks, &[10]);
            assert!(
                else_blocks.is_empty(),
                "Triangle should have no else blocks"
            );
            assert_eq!(*join, Some(20));
        } else {
            panic!("Expected IfThenElse");
        }
    }

    // --- Switch detection tests ---

    #[test]
    fn test_switch_detection() {
        let cfg = build_test_cfg(
            0,
            vec![(
                0,
                vec![(0, Instruction::JumpInd { reg: 3, offset: 0 })],
                vec![],
            )],
        );

        let program = DecodedProgram {
            jump_table: vec![100, 200, 100, 300],
            instructions: vec![(0, Instruction::JumpInd { reg: 3, offset: 0 })],
            code_len: 3,
        };

        let result = StructuralAnalysis::analyze(&cfg, &program);

        let switches: Vec<&Structure> = result
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::Switch { .. }))
            .collect();
        assert_eq!(switches.len(), 1);

        if let Structure::Switch { reg, cases, .. } = switches[0] {
            assert_eq!(*reg, 3);
            // Cases grouped by target: 100->[0,2], 200->[1], 300->[3]
            assert_eq!(cases.len(), 3);
            // Find the case for target 100
            let case_100 = cases.iter().find(|(_, t)| *t == 100).unwrap();
            assert!(case_100.0.contains(&0) && case_100.0.contains(&2));
        } else {
            panic!("Expected Switch");
        }
    }

    // --- Linear CFG (no structures) ---

    #[test]
    fn test_linear_no_structures() {
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
                    vec![(10, Instruction::LoadImm { reg: 1, value: 7 })],
                    vec![20],
                ),
                (20, vec![(20, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        assert!(result.structures.is_empty());
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
    fn test_empty_cfg() {
        let cfg = ControlFlowGraph::new(0);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        assert!(result.structures.is_empty());
        assert!(result.dom_tree.rpo.is_empty());
    }
}
