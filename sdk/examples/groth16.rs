use std::fmt::Debug;

use axiom_circuit::subquery::groth16::default_groth16_subquery_input;
use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomComputeInput, AxiomResult},
    cmd::run_cli,
    halo2_base::AssignedValue,
    Fr,
};

#[AxiomComputeInput]
pub struct Groth16Input {
    pub dummy: u64,
}

impl AxiomComputeFn for Groth16Input {
    fn compute(api: &mut AxiomAPI, _: Groth16CircuitInput<AssignedValue<Fr>>) -> Vec<AxiomResult> {
        let input = default_groth16_subquery_input();
        let assigned_vkey = input
            .vkey_bytes
            .iter()
            .map(|v| api.ctx().load_witness(*v))
            .collect::<Vec<_>>();
        let assigned_proof = input
            .proof_bytes
            .iter()
            .map(|v| api.ctx().load_witness(*v))
            .collect::<Vec<_>>();
        let assigned_public_inputs = input
            .public_inputs
            .iter()
            .map(|v| api.ctx().load_witness(*v))
            .collect::<Vec<_>>();
        api.groth16_verify(
            &assigned_vkey.try_into().unwrap(),
            &assigned_proof.try_into().unwrap(),
            &assigned_public_inputs.try_into().unwrap(),
        );
        vec![]
    }
}

fn main() {
    run_cli::<Groth16Input>();
}
