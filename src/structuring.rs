//! Structural Analysis - Recover High-Level Control Structures from CFG
//!
//! Detects loops, if-then-else, and switch/case patterns from the control flow
//! graph and produces pseudo-code output for human-readable disassembly.

use crate::cfg::ControlFlowGraph;
use crate::decoder::DecodedProgram;
use crate::lifting::LiftedProgram;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use wasm_pvm::pvm::Instruction;

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

#[derive(Debug, Clone)]
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
        if let Some(block) = cfg.blocks.get(&node) {
            for &succ in &block.successors {
                Self::dfs_post_order(cfg, succ, visited, post_order);
            }
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
    pub fn analyze(cfg: &ControlFlowGraph, program: &DecodedProgram) -> Self {
        if cfg.blocks.is_empty() {
            return StructuralAnalysis {
                structures: Vec::new(),
                dom_tree: DominatorTree {
                    idom: HashMap::new(),
                    children: HashMap::new(),
                    rpo: Vec::new(),
                    rpo_index: HashMap::new(),
                    entry: 0,
                },
            };
        }

        let dom_tree = DominatorTree::compute(cfg);
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
    pub fn pseudo_code(
        &self,
        cfg: &ControlFlowGraph,
        mut lifted: Option<&mut LiftedProgram>,
    ) -> String {
        let mut output = String::new();
        output.push_str("=== Pseudo-Code ===\n\n");

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

        // Track which blocks we've already emitted inside structures
        let mut emitted: HashSet<usize> = HashSet::new();

        for &block_pc in &self.dom_tree.rpo {
            if emitted.contains(&block_pc) {
                continue;
            }

            // Emit label if this block has one.
            if let Some(label) = labels.get(&block_pc) {
                let _ = writeln!(output, "{}:", label);
            }

            if let Some(Structure::Loop {
                body, condition, ..
            }) = loop_map.get(&block_pc)
            {
                // Emit loop — declare any undeclared condition variables first.
                if let (Some(cond), Some(ref mut lifted)) =
                    (condition.as_ref(), lifted.as_deref_mut())
                {
                    emit_condition_declarations(cond, cfg, block_pc, lifted, &mut output, "");
                }
                let cond_str = condition
                    .as_ref()
                    .map(|c| format_condition_maybe_lifted(c, cfg, block_pc, lifted.as_deref()))
                    .unwrap_or_else(|| "...".to_string());
                let _ = writeln!(output, "while ({}) {{", cond_str);

                // Emit body blocks (excluding header's own instructions which form the condition)
                self.emit_block_body(cfg, block_pc, &mut output, 1, true, lifted.as_deref_mut());

                let mut body_sorted: Vec<usize> = body.iter().copied().collect();
                body_sorted.sort();
                for &body_pc in &body_sorted {
                    if body_pc == block_pc {
                        continue;
                    }
                    if emitted.contains(&body_pc) {
                        continue;
                    }

                    // Check if this body block is an if-then-else
                    if let Some(Structure::IfThenElse {
                        then_blocks,
                        else_blocks,
                        condition,
                        ..
                    }) = if_map.get(&body_pc)
                    {
                        self.emit_if(
                            cfg,
                            body_pc,
                            then_blocks,
                            else_blocks,
                            condition.as_ref(),
                            &mut output,
                            1,
                            &mut emitted,
                            lifted.as_deref_mut(),
                            &labels,
                        );
                        continue;
                    }

                    self.emit_block_body(
                        cfg,
                        body_pc,
                        &mut output,
                        1,
                        false,
                        lifted.as_deref_mut(),
                    );
                    emitted.insert(body_pc);
                }

                output.push_str("}\n");
                emitted.extend(body.iter());
            } else if let Some(Structure::IfThenElse {
                then_blocks,
                else_blocks,
                condition,
                ..
            }) = if_map.get(&block_pc)
            {
                self.emit_if(
                    cfg,
                    block_pc,
                    then_blocks,
                    else_blocks,
                    condition.as_ref(),
                    &mut output,
                    0,
                    &mut emitted,
                    lifted.as_deref_mut(),
                    &labels,
                );
            } else if let Some(Structure::Switch { reg, cases, .. }) = switch_map.get(&block_pc) {
                // Emit preceding instructions
                self.emit_block_body(cfg, block_pc, &mut output, 0, true, lifted.as_deref_mut());

                // Use lifted variable name for the switch register if available.
                let switch_var = if let Some(ref mut lifted) = lifted {
                    if let Some(branch_pc) = last_instruction_pc(cfg, block_pc) {
                        if let Some(name) = lifted.var_at_use.get(&(branch_pc, *reg)).cloned() {
                            // Declare if not yet declared.
                            if lifted.declared_vars.insert(name.clone()) {
                                let type_str = lifted
                                    .variables
                                    .values()
                                    .find(|v| v.name == name)
                                    .map(|v| format!("{}", v.var_type))
                                    .unwrap_or_else(|| "u64".to_string());
                                let _ = writeln!(output, "let {}: {};", name, type_str);
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
                let _ = writeln!(output, "switch ({}) {{", switch_var);
                for (values, target) in cases.iter() {
                    let vals: Vec<String> = values.iter().map(|v| format!("{}", v)).collect();
                    let target_label = format_goto_target(*target, &labels);
                    let _ = writeln!(
                        output,
                        "    case {}: goto {};",
                        vals.join(", "),
                        target_label
                    );
                }
                output.push_str("}\n");
                emitted.insert(block_pc);
            } else {
                // Plain block
                self.emit_block_body(cfg, block_pc, &mut output, 0, false, lifted.as_deref_mut());
                emitted.insert(block_pc);
            }
        }

        // Emit switch target blocks that weren't reached by the RPO walk.
        // These are separate "entry points" dispatched via indirect jump.
        let mut switch_targets: Vec<usize> = labels
            .keys()
            .copied()
            .filter(|pc| !emitted.contains(pc) && cfg.blocks.contains_key(pc))
            .collect();
        switch_targets.sort();

        for target_pc in switch_targets {
            if emitted.contains(&target_pc) {
                continue;
            }
            let _ = writeln!(output, "{}:", labels[&target_pc]);

            // Emit all blocks reachable from this target in RPO order.
            // Simple BFS forward walk to collect the reachable set.
            let mut reachable = Vec::new();
            let mut visited: HashSet<usize> = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(target_pc);
            while let Some(pc) = queue.pop_front() {
                if !visited.insert(pc) || emitted.contains(&pc) {
                    continue;
                }
                reachable.push(pc);
                emitted.insert(pc);
                if let Some(block) = cfg.blocks.get(&pc) {
                    for &succ in &block.successors {
                        if !visited.contains(&succ) && !emitted.contains(&succ) {
                            queue.push_back(succ);
                        }
                    }
                }
            }

            for &block_pc in &reachable {
                // Check if this block has its own label (and it's not the first one we already emitted).
                if block_pc != target_pc
                    && let Some(label) = labels.get(&block_pc)
                {
                    let _ = writeln!(output, "{}:", label);
                }

                if let Some(Structure::IfThenElse {
                    then_blocks,
                    else_blocks,
                    condition,
                    ..
                }) = if_map.get(&block_pc)
                {
                    self.emit_if(
                        cfg,
                        block_pc,
                        then_blocks,
                        else_blocks,
                        condition.as_ref(),
                        &mut output,
                        0,
                        &mut emitted,
                        lifted.as_deref_mut(),
                        &labels,
                    );
                } else {
                    self.emit_block_body(
                        cfg,
                        block_pc,
                        &mut output,
                        0,
                        false,
                        lifted.as_deref_mut(),
                    );
                }
            }
        }

        fix_blank_lines(&output)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_if(
        &self,
        cfg: &ControlFlowGraph,
        header: usize,
        then_blocks: &[usize],
        else_blocks: &[usize],
        condition: Option<&Condition>,
        output: &mut String,
        indent: usize,
        emitted: &mut HashSet<usize>,
        mut lifted: Option<&mut LiftedProgram>,
        _labels: &HashMap<usize, String>,
    ) {
        let prefix = "    ".repeat(indent);

        // Emit header block instructions (before the branch)
        self.emit_block_body(cfg, header, output, indent, true, lifted.as_deref_mut());

        // Declare any undeclared condition variables.
        if let (Some(cond), Some(ref mut lifted)) = (condition, lifted.as_deref_mut()) {
            emit_condition_declarations(cond, cfg, header, lifted, output, &prefix);
        }
        let cond_str = condition
            .map(|c| format_condition_maybe_lifted(c, cfg, header, lifted.as_deref()))
            .unwrap_or_else(|| "...".to_string());
        let _ = writeln!(output, "{}if ({}) {{", prefix, cond_str);

        for &tb in then_blocks {
            self.emit_block_body(cfg, tb, output, indent + 1, false, lifted.as_deref_mut());
            emitted.insert(tb);
        }

        if !else_blocks.is_empty() {
            let _ = writeln!(output, "{}}} else {{", prefix);
            for &eb in else_blocks {
                self.emit_block_body(cfg, eb, output, indent + 1, false, lifted.as_deref_mut());
                emitted.insert(eb);
            }
        }

        let _ = writeln!(output, "{}}}", prefix);
        emitted.insert(header);
    }

    /// Emit the instructions in a block as pseudo-code lines.
    /// If `skip_terminator` is true, the last instruction (branch/jump) is not emitted.
    /// When `lifted` is provided, uses variable names and skips eliminated PCs.
    fn emit_block_body(
        &self,
        cfg: &ControlFlowGraph,
        block_pc: usize,
        output: &mut String,
        indent: usize,
        skip_terminator: bool,
        mut lifted: Option<&mut LiftedProgram>,
    ) {
        let prefix = "    ".repeat(indent);
        let len_before = output.len();
        if let Some(block) = cfg.blocks.get(&block_pc) {
            let len = block.instructions.len();
            let end = if skip_terminator && len > 0 {
                len - 1
            } else {
                len
            };

            // In lifted mode: pre-scan to collect all variable declarations,
            // emit them at the top of the block (C-style).
            if let Some(ref mut lifted) = lifted {
                let instrs = &block.instructions[..end];
                let decls = lifted.collect_block_declarations(instrs);
                output.push_str(&decls.format(&prefix));
            }

            for (pc, instr) in &block.instructions[..end] {
                if let Some(ref mut lifted) = lifted {
                    // Skip eliminated PCs (folded/propagated).
                    if lifted.eliminated_pcs.contains(pc) {
                        continue;
                    }
                    // Skip noise instructions in lifted mode.
                    if matches!(instr, Instruction::Fallthrough | Instruction::Jump { .. }) {
                        continue;
                    }
                    if let Some(line) = lifted.format_pc(*pc, instr) {
                        let _ = writeln!(output, "{}{}", prefix, line);
                    }
                } else {
                    let _ = writeln!(
                        output,
                        "{}{:#06x}: {}",
                        prefix,
                        pc,
                        format_instruction(instr)
                    );
                }
            }
        }
        // Blank line between basic blocks when content was emitted.
        if output.len() > len_before {
            output.push('\n');
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
fn build_block_labels(cfg: &ControlFlowGraph, structures: &[Structure]) -> HashMap<usize, String> {
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

    // Also label the entry block.
    goto_targets.insert(cfg.entry_pc);

    // Assign labels to all goto targets.
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

/// Emit `let` declarations for any undeclared variables used in a branch condition.
fn emit_condition_declarations(
    cond: &Condition,
    cfg: &ControlFlowGraph,
    header_pc: usize,
    lifted: &mut LiftedProgram,
    output: &mut String,
    prefix: &str,
) {
    use std::fmt::Write;
    let branch_pc = match last_instruction_pc(cfg, header_pc) {
        Some(pc) => pc,
        None => return,
    };
    for operand in [&cond.lhs, &cond.rhs] {
        if let Operand::Reg(reg) = operand
            && let Some(name) = lifted.var_at_use.get(&(branch_pc, *reg)).cloned()
            && lifted.declared_vars.insert(name.clone())
        {
            let type_str = lifted
                .variables
                .values()
                .find(|v| v.name == name)
                .map(|v| format!("{}", v.var_type))
                .unwrap_or_else(|| "u64".to_string());
            let _ = writeln!(output, "{}let {}: {};", prefix, name, type_str);
        }
    }
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
fn format_condition_lifted(cond: &Condition, branch_pc: usize, lifted: &LiftedProgram) -> String {
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
    match instr {
        Instruction::Trap => "trap".to_string(),
        Instruction::Fallthrough => "fallthrough".to_string(),

        Instruction::LoadImm { reg, value } => format!("r{} = {}", reg, value),
        Instruction::LoadImm64 { reg, value } => format!("r{} = {}", reg, value),

        Instruction::Add32 { dst, src1, src2 } => {
            format!("r{} = r{} + r{}", dst, src1, src2)
        }
        Instruction::Sub32 { dst, src1, src2 } => {
            format!("r{} = r{} - r{}", dst, src1, src2)
        }
        Instruction::Mul32 { dst, src1, src2 } => {
            format!("r{} = r{} * r{}", dst, src1, src2)
        }
        Instruction::DivU32 { dst, src1, src2 } => {
            format!("r{} = r{} /u r{}", dst, src1, src2)
        }
        Instruction::DivS32 { dst, src1, src2 } => {
            format!("r{} = r{} /s r{}", dst, src1, src2)
        }
        Instruction::RemU32 { dst, src1, src2 } => {
            format!("r{} = r{} %u r{}", dst, src1, src2)
        }
        Instruction::RemS32 { dst, src1, src2 } => {
            format!("r{} = r{} %s r{}", dst, src1, src2)
        }
        Instruction::And { dst, src1, src2 } => {
            format!("r{} = r{} & r{}", dst, src1, src2)
        }
        Instruction::Or { dst, src1, src2 } => {
            format!("r{} = r{} | r{}", dst, src1, src2)
        }
        Instruction::Xor { dst, src1, src2 } => {
            format!("r{} = r{} ^ r{}", dst, src1, src2)
        }
        Instruction::ShloL32 { dst, src1, src2 } => {
            format!("r{} = r{} << r{}", dst, src1, src2)
        }
        Instruction::ShloR32 { dst, src1, src2 } => {
            format!("r{} = r{} >>u r{}", dst, src1, src2)
        }
        Instruction::SharR32 { dst, src1, src2 } => {
            format!("r{} = r{} >>s r{}", dst, src1, src2)
        }
        Instruction::Add64 { dst, src1, src2 } => {
            format!("r{} = r{} +64 r{}", dst, src1, src2)
        }
        Instruction::Sub64 { dst, src1, src2 } => {
            format!("r{} = r{} -64 r{}", dst, src1, src2)
        }
        Instruction::Mul64 { dst, src1, src2 } => {
            format!("r{} = r{} *64 r{}", dst, src1, src2)
        }
        Instruction::DivU64 { dst, src1, src2 } => {
            format!("r{} = r{} /u64 r{}", dst, src1, src2)
        }
        Instruction::DivS64 { dst, src1, src2 } => {
            format!("r{} = r{} /s64 r{}", dst, src1, src2)
        }
        Instruction::RemU64 { dst, src1, src2 } => {
            format!("r{} = r{} %u64 r{}", dst, src1, src2)
        }
        Instruction::RemS64 { dst, src1, src2 } => {
            format!("r{} = r{} %s64 r{}", dst, src1, src2)
        }
        Instruction::ShloL64 { dst, src1, src2 } => {
            format!("r{} = r{} <<64 r{}", dst, src1, src2)
        }
        Instruction::ShloR64 { dst, src1, src2 } => {
            format!("r{} = r{} >>u64 r{}", dst, src1, src2)
        }
        Instruction::SharR64 { dst, src1, src2 } => {
            format!("r{} = r{} >>s64 r{}", dst, src1, src2)
        }
        Instruction::SetLtU { dst, src1, src2 } => {
            format!("r{} = r{} <u r{}", dst, src1, src2)
        }
        Instruction::SetLtS { dst, src1, src2 } => {
            format!("r{} = r{} <s r{}", dst, src1, src2)
        }

        Instruction::AddImm32 { dst, src, value } => {
            format!("r{} = r{} + {}", dst, src, value)
        }
        Instruction::AddImm64 { dst, src, value } => {
            format!("r{} = r{} +64 {}", dst, src, value)
        }
        Instruction::SetLtUImm { dst, src, value } => {
            format!("r{} = r{} <u {}", dst, src, value)
        }
        Instruction::SetLtSImm { dst, src, value } => {
            format!("r{} = r{} <s {}", dst, src, value)
        }

        Instruction::Sbrk { dst, src } => format!("r{} = sbrk(r{})", dst, src),
        Instruction::CountSetBits64 { dst, src } => format!("r{} = popcnt64(r{})", dst, src),
        Instruction::CountSetBits32 { dst, src } => format!("r{} = popcnt32(r{})", dst, src),
        Instruction::LeadingZeroBits64 { dst, src } => format!("r{} = clz64(r{})", dst, src),
        Instruction::LeadingZeroBits32 { dst, src } => format!("r{} = clz32(r{})", dst, src),
        Instruction::TrailingZeroBits64 { dst, src } => format!("r{} = ctz64(r{})", dst, src),
        Instruction::TrailingZeroBits32 { dst, src } => format!("r{} = ctz32(r{})", dst, src),
        Instruction::SignExtend8 { dst, src } => format!("r{} = sext8(r{})", dst, src),
        Instruction::SignExtend16 { dst, src } => format!("r{} = sext16(r{})", dst, src),
        Instruction::ZeroExtend16 { dst, src } => format!("r{} = zext16(r{})", dst, src),

        Instruction::Jump { offset } => format!("jump {}", offset),
        Instruction::JumpInd { reg, .. } => format!("jump_ind r{}", reg),

        Instruction::LoadIndU8 { dst, base, offset } => {
            format!("r{} = u8[r{} + {}]", dst, base, offset)
        }
        Instruction::LoadIndI8 { dst, base, offset } => {
            format!("r{} = i8[r{} + {}]", dst, base, offset)
        }
        Instruction::LoadIndU16 { dst, base, offset } => {
            format!("r{} = u16[r{} + {}]", dst, base, offset)
        }
        Instruction::LoadIndI16 { dst, base, offset } => {
            format!("r{} = i16[r{} + {}]", dst, base, offset)
        }
        Instruction::LoadIndU32 { dst, base, offset } => {
            format!("r{} = u32[r{} + {}]", dst, base, offset)
        }
        Instruction::LoadIndU64 { dst, base, offset } => {
            format!("r{} = u64[r{} + {}]", dst, base, offset)
        }

        Instruction::StoreIndU8 { base, src, offset } => {
            format!("u8[r{} + {}] = r{}", base, offset, src)
        }
        Instruction::StoreIndU16 { base, src, offset } => {
            format!("u16[r{} + {}] = r{}", base, offset, src)
        }
        Instruction::StoreIndU32 { base, src, offset } => {
            format!("u32[r{} + {}] = r{}", base, offset, src)
        }
        Instruction::StoreIndU64 { base, src, offset } => {
            format!("u64[r{} + {}] = r{}", base, offset, src)
        }

        Instruction::BranchEqImm { reg, value, offset } => {
            format!("if (r{} == {}) jump {}", reg, value, offset)
        }
        Instruction::BranchNeImm { reg, value, offset } => {
            format!("if (r{} != {}) jump {}", reg, value, offset)
        }
        Instruction::BranchGeSImm { reg, value, offset } => {
            format!("if (r{} >=s {}) jump {}", reg, value, offset)
        }
        Instruction::BranchGeU { reg1, reg2, offset } => {
            format!("if (r{} >=u r{}) jump {}", reg1, reg2, offset)
        }
        Instruction::BranchLtU { reg1, reg2, offset } => {
            format!("if (r{} <u r{}) jump {}", reg1, reg2, offset)
        }

        Instruction::Ecalli { index } => format!("ecalli {}", index),
    }
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
        let pseudo = result.pseudo_code(&cfg, None);

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
        let pseudo = result.pseudo_code(&cfg, None);

        assert!(pseudo.contains("if"), "Should contain 'if': {}", pseudo);
        assert!(
            pseudo.contains("r1 != 5"),
            "Should contain condition: {}",
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
