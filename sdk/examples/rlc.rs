use std::fmt::Debug;

use axiom_circuit::axiom_eth::rlc::circuit::builder::RlcCircuitBuilder;
use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomResult},
    cmd::run_cli,
    halo2_base::{
        gates::{RangeChip, RangeInstructions},
        AssignedValue,
    },
    AxiomComputeInput, Fr,
};

#[AxiomComputeInput]
pub struct RlcInput {
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl AxiomComputeFn for RlcInput {
    type FirstPhasePayload = Vec<AssignedValue<Fr>>;

    fn compute(_: &mut AxiomAPI, _: RlcCircuitInput<AssignedValue<Fr>>) -> Vec<AxiomResult> {
        unimplemented!()
    }

    fn compute_phase0(
        _: &mut AxiomAPI,
        assigned_inputs: Self::Input<AssignedValue<Fr>>,
    ) -> (Vec<AxiomResult>, Self::FirstPhasePayload) {
        (
            vec![],
            vec![assigned_inputs.a, assigned_inputs.b, assigned_inputs.c],
        )
    }

    fn compute_phase1(
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
        payload: Self::FirstPhasePayload,
    ) {
        let gate = range.gate();
        let rlc_chip = builder.rlc_chip(gate);
        rlc_chip.compute_rlc_fixed_len(builder.base.main(1), payload);
    }
}

fn main() {
    env_logger::init();
    run_cli::<RlcInput>();
}
