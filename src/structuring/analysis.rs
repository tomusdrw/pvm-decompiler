use super::{StructuralAnalysis, Structure, extract_condition};
use crate::cfg::ControlFlowGraph;
use crate::decoder::DecodedProgram;
use std::collections::{HashMap, HashSet, VecDeque};
use wasm_pvm::pvm::Instruction;

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

impl StructuralAnalysis {
    /// Run structural analysis on a CFG.
    /// Convenience method that computes its own dominator tree.
    /// Use `analyze_with_dom_tree` when sharing a pre-computed tree.
    #[cfg(test)]
    pub fn analyze(cfg: &ControlFlowGraph, program: &DecodedProgram) -> Self {
        let dom_tree = DominatorTree::compute(cfg);
        Self::analyze_with_dom_tree(cfg, program, dom_tree, HashSet::new())
    }

    /// Run structural analysis reusing a pre-computed dominator tree.
    pub fn analyze_with_dom_tree(
        cfg: &ControlFlowGraph,
        program: &DecodedProgram,
        dom_tree: DominatorTree,
        function_entry_pcs: HashSet<usize>,
    ) -> Self {
        if cfg.blocks.is_empty() {
            return StructuralAnalysis {
                structures: Vec::new(),
                dom_tree,
            };
        }
        let mut structures = Vec::new();
        let sccs = Self::compute_sccs(cfg);

        // Detect switches early so dispatch infrastructure can be excluded from
        // user loop recovery.
        let switches = Self::detect_switches(cfg, program, &function_entry_pcs);
        let dispatch_scc_blocks = Self::collect_dispatch_scc_blocks(&switches, &sccs);
        let irreducible_scc_blocks = Self::collect_irreducible_scc_blocks(cfg, &sccs);

        // Detect reducible loops (back-edges where target dominates source),
        // skipping SCCs marked as dispatch infrastructure.
        let loops = Self::detect_loops(cfg, &dom_tree, &dispatch_scc_blocks);
        structures.extend(loops);

        // Collect loop headers for exclusion in if-then-else detection
        let loop_headers: HashSet<usize> = structures
            .iter()
            .filter_map(|s| match s {
                Structure::Loop { header, .. } => Some(*header),
                _ => None,
            })
            .collect();
        let mut excluded_if_headers = loop_headers;
        excluded_if_headers.extend(dispatch_scc_blocks.iter().copied());
        excluded_if_headers.extend(irreducible_scc_blocks.iter().copied());

        // Detect if-then-else patterns
        let ifs = Self::detect_if_then_else(cfg, &dom_tree, &excluded_if_headers);
        structures.extend(ifs);

        // Detect switch/case patterns
        structures.extend(switches);

        StructuralAnalysis {
            structures,
            dom_tree,
        }
    }

    /// Compute strongly connected components using iterative Kosaraju.
    /// Components are sorted by their minimum block PC for determinism.
    fn compute_sccs(cfg: &ControlFlowGraph) -> Vec<HashSet<usize>> {
        let mut nodes: Vec<usize> = cfg.blocks.keys().copied().collect();
        nodes.sort_unstable();

        // Precompute sorted adjacency lists once; avoids repeatedly cloning
        // successors/predecessors while traversing large graphs.
        let mut succ_index: HashMap<usize, Vec<usize>> = HashMap::with_capacity(nodes.len());
        let mut pred_index: HashMap<usize, Vec<usize>> = HashMap::with_capacity(nodes.len());
        for &node in &nodes {
            let mut succs = cfg
                .blocks
                .get(&node)
                .map(|b| b.successors.clone())
                .unwrap_or_default();
            succs.sort_unstable();
            succ_index.insert(node, succs);

            let mut preds = cfg
                .blocks
                .get(&node)
                .map(|b| b.predecessors.clone())
                .unwrap_or_default();
            preds.sort_unstable();
            pred_index.insert(node, preds);
        }

        let mut visited = HashSet::new();
        let mut finish_order = Vec::new();

        for &start in &nodes {
            if !visited.insert(start) {
                continue;
            }
            let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
            while let Some((node, idx)) = stack.last_mut() {
                let succs = succ_index.get(node).map(Vec::as_slice).unwrap_or(&[]);
                if *idx < succs.len() {
                    let succ = succs[*idx];
                    *idx += 1;
                    if visited.insert(succ) {
                        stack.push((succ, 0));
                    }
                } else {
                    let n = *node;
                    stack.pop();
                    finish_order.push(n);
                }
            }
        }

        let mut assigned = HashSet::new();
        let mut sccs = Vec::<HashSet<usize>>::new();
        for &start in finish_order.iter().rev() {
            if !assigned.insert(start) {
                continue;
            }
            let mut component = HashSet::new();
            let mut stack = vec![start];
            while let Some(node) = stack.pop() {
                component.insert(node);
                let preds = pred_index.get(&node).map(Vec::as_slice).unwrap_or(&[]);
                for &pred in preds {
                    if assigned.insert(pred) {
                        stack.push(pred);
                    }
                }
            }
            sccs.push(component);
        }

        sccs.sort_by_key(|scc| scc.iter().min().copied().unwrap_or(usize::MAX));
        sccs
    }

    /// Expand dispatch switch headers to their whole SCCs so loop recovery can
    /// skip dispatch infrastructure regions explicitly.
    fn collect_dispatch_scc_blocks(
        switches: &[Structure],
        sccs: &[HashSet<usize>],
    ) -> HashSet<usize> {
        let dispatch_headers: HashSet<usize> = switches
            .iter()
            .filter_map(|s| match s {
                Structure::Switch {
                    header,
                    is_dispatch: true,
                    ..
                } => Some(*header),
                _ => None,
            })
            .collect();
        if dispatch_headers.is_empty() {
            return HashSet::new();
        }

        let mut blocks = HashSet::new();
        for scc in sccs {
            if scc.iter().any(|b| dispatch_headers.contains(b)) {
                blocks.extend(scc.iter().copied());
            }
        }
        blocks
    }

    /// Collect irreducible SCC blocks (multi-entry SCCs). These regions are
    /// left for explicit unstructured fallback (labeled goto) instead of being
    /// forced into if/loop shapes.
    fn collect_irreducible_scc_blocks(
        cfg: &ControlFlowGraph,
        sccs: &[HashSet<usize>],
    ) -> HashSet<usize> {
        let mut blocks = HashSet::new();

        for scc in sccs {
            // Single-node SCCs are trivially reducible for our purposes here.
            if scc.len() <= 1 {
                continue;
            }

            let mut entry_nodes = HashSet::new();
            for &node in scc {
                if let Some(block) = cfg.blocks.get(&node)
                    && block.predecessors.iter().any(|pred| !scc.contains(pred))
                {
                    entry_nodes.insert(node);
                }
            }

            if entry_nodes.len() > 1 {
                blocks.extend(scc.iter().copied());
            }
        }

        blocks
    }

    /// Detect reducible natural loops by finding back-edges.
    fn detect_loops(
        cfg: &ControlFlowGraph,
        dom_tree: &DominatorTree,
        dispatch_scc_blocks: &HashSet<usize>,
    ) -> Vec<Structure> {
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
                    if !Self::is_reducible_loop_region(cfg, dom_tree, header, &body) {
                        continue;
                    }
                    if body.iter().all(|b| dispatch_scc_blocks.contains(b)) {
                        continue;
                    }

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
        loops.dedup_by_key(|l| match l {
            Structure::Loop { header, .. } => *header,
            _ => 0,
        });
        loops
    }

    /// A loop region is reducible iff it has exactly one entry edge from outside
    /// and that entry is the loop header, which also dominates all loop nodes.
    /// For loops headed at the CFG entry block, zero external entries is valid.
    fn is_reducible_loop_region(
        cfg: &ControlFlowGraph,
        dom_tree: &DominatorTree,
        header: usize,
        body: &HashSet<usize>,
    ) -> bool {
        if body.is_empty() || !body.contains(&header) {
            return false;
        }
        if body.iter().any(|&n| !dom_tree.dominates(header, n)) {
            return false;
        }

        let mut entry_nodes = HashSet::new();
        for &node in body {
            if let Some(block) = cfg.blocks.get(&node)
                && block.predecessors.iter().any(|pred| !body.contains(pred))
            {
                entry_nodes.insert(node);
            }
        }

        if header == cfg.entry_pc && entry_nodes.is_empty() {
            return true;
        }

        entry_nodes.len() == 1 && entry_nodes.contains(&header)
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
        excluded_headers: &HashSet<usize>,
    ) -> Vec<Structure> {
        let mut ifs = Vec::new();

        for &block_pc in &dom_tree.rpo {
            let block = match cfg.blocks.get(&block_pc) {
                Some(b) => b,
                None => continue,
            };

            // Only consider 2-successor blocks that are eligible for structured IFs.
            if block.successors.len() != 2 || excluded_headers.contains(&block_pc) {
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
    fn detect_switches(
        cfg: &ControlFlowGraph,
        program: &DecodedProgram,
        function_entry_pcs: &HashSet<usize>,
    ) -> Vec<Structure> {
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

                // In PVM, JumpInd with the global jump table is always dispatch
                // infrastructure routing between functions. When we have function
                // detection (function_entry_pcs is non-empty), all JumpInd-based
                // switches are dispatch. User-level switch/case (br_table) is
                // compiled to conditional branches, not JumpInd.
                let is_dispatch = !function_entry_pcs.is_empty();

                switches.push(Structure::Switch {
                    header: block.start_pc,
                    reg: *reg,
                    cases,
                    is_dispatch,
                });
            }
        }

        switches
    }
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
    fn test_entry_header_loop_is_reducible() {
        // Entry-header loop:
        // 0 (header) -> 8 (exit) or 4 (body)
        // 4 -> 0 (back-edge)
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
                (4, vec![(4, Instruction::Jump { offset: -4 })], vec![0]),
                (8, vec![(8, Instruction::Trap)], vec![]),
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
            assert_eq!(*header, 0);
            assert_eq!(*latch, 4);
            assert!(body.contains(&0));
            assert!(body.contains(&4));
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

    #[test]
    fn test_dispatch_switch_scc_blocks_are_excluded_from_loop_recovery() {
        // Dispatch-like SCC:
        // 0 (JumpInd dispatch switch) -> 4 and 8
        // 4 -> 0 (back-edge inside dispatch infrastructure)
        // 8 -> trap
        //
        // With non-empty function entries this switch is marked dispatch; the
        // SCC {0,4} must be excluded from user loop recovery.
        let cfg = build_test_cfg(
            0,
            vec![
                (
                    0,
                    vec![(0, Instruction::JumpInd { reg: 3, offset: 0 })],
                    vec![4, 8],
                ),
                (4, vec![(4, Instruction::Jump { offset: -4 })], vec![0]),
                (8, vec![(8, Instruction::Trap)], vec![]),
            ],
        );
        let dom_tree = DominatorTree::compute(&cfg);
        let program = DecodedProgram {
            jump_table: vec![4, 8, 4],
            instructions: vec![(0, Instruction::JumpInd { reg: 3, offset: 0 })],
            memory_base: None,
            code_len: 9,
        };
        let function_entry_pcs: HashSet<usize> = [0].into_iter().collect();

        let result =
            StructuralAnalysis::analyze_with_dom_tree(&cfg, &program, dom_tree, function_entry_pcs);

        let loop_count = result
            .structures
            .iter()
            .filter(|s| matches!(s, Structure::Loop { .. }))
            .count();
        assert_eq!(
            loop_count, 0,
            "Dispatch SCC loop should not be recovered as user loop"
        );

        let dispatch_switch = result.structures.iter().find(|s| {
            matches!(
                s,
                Structure::Switch {
                    header: 0,
                    is_dispatch: true,
                    ..
                }
            )
        });
        assert!(
            dispatch_switch.is_some(),
            "Dispatch switch should still be recorded"
        );
    }

    #[test]
    fn test_irreducible_scc_blocks_are_excluded_from_if_recovery() {
        // Irreducible SCC:
        // 10 branches into both 20 and 30 (two entries into SCC {20,30})
        // 20 -> 30 or exit 50
        // 30 -> 20
        // This SCC should not be force-recovered as structured IF/loop headers.
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
                    vec![30, 50],
                ),
                (30, vec![(30, Instruction::Jump { offset: -10 })], vec![20]),
                (50, vec![(50, Instruction::Trap)], vec![]),
            ],
        );

        let result = StructuralAnalysis::analyze(&cfg, &empty_program());

        assert!(
            !result.structures.iter().any(|s| matches!(
                s,
                Structure::IfThenElse {
                    header: 20 | 30,
                    ..
                }
            )),
            "Irreducible SCC headers must stay unstructured"
        );
        assert!(
            !result.structures.iter().any(|s| matches!(
                s,
                Structure::Loop {
                    header: 20 | 30,
                    ..
                }
            )),
            "Irreducible SCC headers must not be forced into loop recovery"
        );
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
            memory_base: None,
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

    #[test]
    fn test_empty_cfg() {
        let cfg = crate::cfg::ControlFlowGraph::new(0);
        let result = StructuralAnalysis::analyze(&cfg, &empty_program());
        assert!(result.structures.is_empty());
        assert!(result.dom_tree.rpo.is_empty());
    }
}
