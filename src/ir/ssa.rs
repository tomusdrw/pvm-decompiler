//! Minimal SSA backbone used for correctness proofs in optimization passes.
//!
//! This builds an SSA-like value graph over register definitions and uses:
//! - explicit value IDs for instruction defs
//! - merge handling via synthetic phi values at join blocks
//! - value-at-use lookup for each (pc, reg) use site
//!
//! The representation is intentionally lightweight and local to analyses that
//! need proof-style checks (e.g., dominance-safe inlining/folding).

use crate::cfg::ControlFlowGraph;
use crate::instruction::InstructionShape;
use crate::structuring::DominatorTree;
use std::collections::{BTreeSet, HashMap, HashSet};

pub type SsaValueId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaValueKind {
    Param { reg: u8 },
    Undef { reg: u8 },
    Instr { pc: usize, reg: u8, block_pc: usize },
    Phi { block_pc: usize, reg: u8 },
}

#[derive(Debug, Clone)]
pub struct SsaValue {
    pub kind: SsaValueKind,
    pub operands: Vec<SsaValueId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SsaUseSite {
    Instr { pc: usize, reg: u8 },
    PhiOperand { block_pc: usize, reg: u8 },
}

#[derive(Debug)]
pub struct SsaProgram {
    pub values: Vec<SsaValue>,
    def_value_by_pc_reg: HashMap<(usize, u8), SsaValueId>,
    use_value_by_pc_reg: HashMap<(usize, u8), SsaValueId>,
    uses_by_value: HashMap<SsaValueId, Vec<SsaUseSite>>,
    #[allow(dead_code)]
    phi_value_by_block_reg: HashMap<(usize, u8), SsaValueId>,
    pc_to_block: HashMap<usize, usize>,
}

impl SsaProgram {
    pub fn build(cfg: &ControlFlowGraph, dom_tree: &DominatorTree) -> Self {
        let mut values = Vec::<SsaValue>::new();
        let mut def_value_by_pc_reg = HashMap::<(usize, u8), SsaValueId>::new();
        let mut use_value_by_pc_reg = HashMap::<(usize, u8), SsaValueId>::new();
        let mut uses_by_value = HashMap::<SsaValueId, Vec<SsaUseSite>>::new();
        let mut phi_value_by_block_reg = HashMap::<(usize, u8), SsaValueId>::new();

        let mut pc_to_block = HashMap::new();
        for block in cfg.blocks.values() {
            for (pc, _) in &block.instructions {
                pc_to_block.insert(*pc, block.start_pc);
            }
        }

        // PVM has 13 GP registers (r0..r12); include all to keep states total.
        let regs: Vec<u8> = (0..=12).collect();

        let mut param_value_by_reg = HashMap::<u8, SsaValueId>::new();
        let mut undef_value_by_reg = HashMap::<u8, SsaValueId>::new();
        for &reg in &regs {
            let param_id = new_value(&mut values, SsaValueKind::Param { reg });
            let undef_id = new_value(&mut values, SsaValueKind::Undef { reg });
            param_value_by_reg.insert(reg, param_id);
            undef_value_by_reg.insert(reg, undef_id);
        }

        let mut sorted_blocks: Vec<usize> = cfg.blocks.keys().copied().collect();
        sorted_blocks.sort();
        for &block_pc in &sorted_blocks {
            if let Some(block) = cfg.blocks.get(&block_pc) {
                for (pc, instr) in &block.instructions {
                    let (mut defs, _) = InstructionShape::classify(instr).def_use();
                    defs.sort_unstable();
                    defs.dedup();
                    for reg in defs {
                        let value_id = new_value(
                            &mut values,
                            SsaValueKind::Instr {
                                pc: *pc,
                                reg,
                                block_pc,
                            },
                        );
                        def_value_by_pc_reg.insert((*pc, reg), value_id);
                    }
                }
            }
        }

        let mut order = dom_tree.rpo.clone();
        let mut in_order: HashSet<usize> = order.iter().copied().collect();
        for block_pc in &sorted_blocks {
            if in_order.insert(*block_pc) {
                order.push(*block_pc);
            }
        }

        let mut block_in: HashMap<usize, HashMap<u8, SsaValueId>> = HashMap::new();
        let mut block_out: HashMap<usize, HashMap<u8, SsaValueId>> = HashMap::new();

        // Iterative fixed-point to resolve loop-carried phi dependencies.
        let mut changed = true;
        let max_iterations = cfg.blocks.len().max(1) * 20;
        let mut iterations = 0usize;
        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;

            for &block_pc in &order {
                let Some(block) = cfg.blocks.get(&block_pc) else {
                    continue;
                };

                let mut in_map: HashMap<u8, SsaValueId> = HashMap::new();
                if block.predecessors.is_empty() {
                    for &reg in &regs {
                        let val = if block_pc == cfg.entry_pc {
                            param_value_by_reg[&reg]
                        } else {
                            undef_value_by_reg[&reg]
                        };
                        in_map.insert(reg, val);
                    }
                } else {
                    for &reg in &regs {
                        let mut incoming = BTreeSet::new();
                        for pred in &block.predecessors {
                            if let Some(pred_out) = block_out.get(pred)
                                && let Some(v) = pred_out.get(&reg)
                            {
                                incoming.insert(*v);
                            }
                        }

                        let merged = if incoming.is_empty() {
                            undef_value_by_reg[&reg]
                        } else if incoming.len() == 1 {
                            *incoming.iter().next().expect("incoming has one value")
                        } else {
                            let key = (block_pc, reg);
                            if let Some(id) = phi_value_by_block_reg.get(&key).copied() {
                                id
                            } else {
                                let id =
                                    new_value(&mut values, SsaValueKind::Phi { block_pc, reg });
                                phi_value_by_block_reg.insert(key, id);
                                id
                            }
                        };
                        in_map.insert(reg, merged);
                    }
                }

                if block_in.get(&block_pc) != Some(&in_map) {
                    block_in.insert(block_pc, in_map.clone());
                    changed = true;
                }

                let mut out_map = in_map;
                for (pc, instr) in &block.instructions {
                    let (mut defs, _) = InstructionShape::classify(instr).def_use();
                    defs.sort_unstable();
                    defs.dedup();
                    for reg in defs {
                        if let Some(value_id) = def_value_by_pc_reg.get(&(*pc, reg)).copied() {
                            out_map.insert(reg, value_id);
                        }
                    }
                }

                if block_out.get(&block_pc) != Some(&out_map) {
                    block_out.insert(block_pc, out_map);
                    changed = true;
                }
            }
        }

        // Populate phi operands from converged predecessor out states.
        let mut phi_entries: Vec<((usize, u8), SsaValueId)> = phi_value_by_block_reg
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        phi_entries.sort_by_key(|((block_pc, reg), _)| (*block_pc, *reg));
        for ((block_pc, reg), phi_id) in phi_entries {
            let Some(block) = cfg.blocks.get(&block_pc) else {
                continue;
            };
            let mut incoming = BTreeSet::new();
            for pred in &block.predecessors {
                if let Some(pred_out) = block_out.get(pred)
                    && let Some(v) = pred_out.get(&reg)
                {
                    incoming.insert(*v);
                }
            }
            if incoming.len() <= 1 {
                continue;
            }

            let operands: Vec<SsaValueId> = incoming.iter().copied().collect();
            values[phi_id].operands = operands.clone();
            for op in operands {
                uses_by_value
                    .entry(op)
                    .or_default()
                    .push(SsaUseSite::PhiOperand { block_pc, reg });
            }
        }

        // Populate per-instruction use mapping using converged in states.
        for &block_pc in &order {
            let Some(block) = cfg.blocks.get(&block_pc) else {
                continue;
            };
            let mut cur = block_in.get(&block_pc).cloned().unwrap_or_else(|| {
                let mut state = HashMap::new();
                for &reg in &regs {
                    state.insert(reg, undef_value_by_reg[&reg]);
                }
                state
            });

            for (pc, instr) in &block.instructions {
                let (mut defs, mut uses) = InstructionShape::classify(instr).def_use();
                defs.sort_unstable();
                defs.dedup();
                uses.sort_unstable();
                uses.dedup();

                for reg in uses {
                    let value = cur
                        .get(&reg)
                        .copied()
                        .unwrap_or_else(|| undef_value_by_reg[&reg]);
                    use_value_by_pc_reg.insert((*pc, reg), value);
                    uses_by_value
                        .entry(value)
                        .or_default()
                        .push(SsaUseSite::Instr { pc: *pc, reg });
                }

                for reg in defs {
                    if let Some(value_id) = def_value_by_pc_reg.get(&(*pc, reg)).copied() {
                        cur.insert(reg, value_id);
                    }
                }
            }
        }

        for uses in uses_by_value.values_mut() {
            uses.sort();
            uses.dedup();
        }

        SsaProgram {
            values,
            def_value_by_pc_reg,
            use_value_by_pc_reg,
            uses_by_value,
            phi_value_by_block_reg,
            pc_to_block,
        }
    }

    pub fn value_for_def_pc_reg(&self, pc: usize, reg: u8) -> Option<SsaValueId> {
        self.def_value_by_pc_reg.get(&(pc, reg)).copied()
    }

    #[allow(dead_code)]
    pub fn value_for_use_pc_reg(&self, pc: usize, reg: u8) -> Option<SsaValueId> {
        self.use_value_by_pc_reg.get(&(pc, reg)).copied()
    }

    #[allow(dead_code)]
    pub fn phi_value_for_block_reg(&self, block_pc: usize, reg: u8) -> Option<SsaValueId> {
        self.phi_value_by_block_reg.get(&(block_pc, reg)).copied()
    }

    pub fn use_mappings(&self) -> &HashMap<(usize, u8), SsaValueId> {
        &self.use_value_by_pc_reg
    }

    pub fn value_kind(&self, value: SsaValueId) -> Option<&SsaValueKind> {
        self.values.get(value).map(|v| &v.kind)
    }

    pub fn value_operands(&self, value: SsaValueId) -> Option<&[SsaValueId]> {
        self.values.get(value).map(|v| v.operands.as_slice())
    }

    pub fn use_count(&self, value: SsaValueId) -> usize {
        self.uses_by_value.get(&value).map(|u| u.len()).unwrap_or(0)
    }

    /// Returns the PC only when the value has exactly one instruction use and
    /// no phi-operand uses.
    pub fn single_instruction_use_pc(&self, value: SsaValueId) -> Option<usize> {
        let uses = self.uses_by_value.get(&value)?;
        if uses
            .iter()
            .any(|u| matches!(u, SsaUseSite::PhiOperand { .. }))
        {
            return None;
        }
        let mut pcs = uses.iter().filter_map(|u| match u {
            SsaUseSite::Instr { pc, .. } => Some(*pc),
            SsaUseSite::PhiOperand { .. } => None,
        });
        let first = pcs.next()?;
        if pcs.next().is_some() {
            return None;
        }
        Some(first)
    }

    pub fn value_definition_dominates_use_pc(
        &self,
        value: SsaValueId,
        use_pc: usize,
        dom_tree: &DominatorTree,
    ) -> bool {
        let use_block = match self.pc_to_block.get(&use_pc).copied() {
            Some(b) => b,
            None => return false,
        };
        let Some(value) = self.values.get(value) else {
            return false;
        };

        match value.kind {
            SsaValueKind::Param { .. } => true,
            SsaValueKind::Undef { .. } => false,
            SsaValueKind::Instr { block_pc, .. } | SsaValueKind::Phi { block_pc, .. } => {
                dom_tree.dominates(block_pc, use_block)
            }
        }
    }
}

fn new_value(values: &mut Vec<SsaValue>, kind: SsaValueKind) -> SsaValueId {
    let id = values.len();
    values.push(SsaValue {
        kind,
        operands: Vec::new(),
    });
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_test_cfg;
    use wasm_pvm::pvm::Instruction;

    #[test]
    fn test_ssa_build_creates_phi_on_merge() {
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
                        (10, Instruction::LoadImm { reg: 1, value: 1 }),
                        (14, Instruction::Jump { offset: 16 }),
                    ],
                    vec![30],
                ),
                (
                    20,
                    vec![
                        (20, Instruction::LoadImm { reg: 1, value: 2 }),
                        (24, Instruction::Jump { offset: 6 }),
                    ],
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
                                src2: 0,
                            },
                        ),
                        (34, Instruction::Trap),
                    ],
                    vec![],
                ),
            ],
        );

        let dom_tree = DominatorTree::compute(&cfg);
        let ssa = SsaProgram::build(&cfg, &dom_tree);

        let phi = ssa
            .phi_value_for_block_reg(30, 1)
            .expect("merge block should have phi for r1");
        assert_eq!(
            ssa.value_for_use_pc_reg(30, 1),
            Some(phi),
            "use of r1 in merge block should consume phi value"
        );

        let def_a = ssa
            .value_for_def_pc_reg(10, 1)
            .expect("def in then branch should exist");
        let def_b = ssa
            .value_for_def_pc_reg(20, 1)
            .expect("def in else branch should exist");
        let operands = &ssa.values[phi].operands;
        assert_eq!(operands.len(), 2, "phi should have two incoming operands");
        assert!(operands.contains(&def_a));
        assert!(operands.contains(&def_b));
    }

    #[test]
    fn test_ssa_single_use_and_dominance_proof() {
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
        let value = ssa
            .value_for_def_pc_reg(0, 1)
            .expect("def at pc 0 for r1 should exist");
        assert_eq!(ssa.use_count(value), 1, "value should have one use");
        assert_eq!(
            ssa.single_instruction_use_pc(value),
            Some(4),
            "single use should be at pc 4"
        );
        assert!(
            ssa.value_definition_dominates_use_pc(value, 4, &dom_tree),
            "definition should dominate the use"
        );
    }
}
