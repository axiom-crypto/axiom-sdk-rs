use std::fmt::Debug;

use axiom_circuit::subquery::groth16::parse_groth16_input;
use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomComputeInput, AxiomResult},
    cmd::run_cli,
    halo2_base::AssignedValue,
    subquery::groth16::assign_groth16_input,
    Fr,
};

#[AxiomComputeInput]
pub struct Groth16ClientInput {
    pub dummy: u64,
}

const DEFAULT_JSON: &str = include_str!("../data/groth16/default.json");
const DEFAULT_PROOF_JSON: &str = include_str!("../data/groth16/default_proof.json");
const DEFAULT_PUBLIC_INPUTS_JSON: &str = include_str!("../data/groth16/default_public_inputs.json");

impl AxiomComputeFn for Groth16ClientInput {
    fn compute(
        api: &mut AxiomAPI,
        _: Groth16ClientCircuitInput<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult> {
        let input = parse_groth16_input(
            DEFAULT_JSON.to_string(),
            DEFAULT_PROOF_JSON.to_string(),
            DEFAULT_PUBLIC_INPUTS_JSON.to_string(),
        );
        let (assigned_vkey, assigned_proof, assigned_public_inputs) =
            assign_groth16_input(api, input);
        api.groth16_verify(
            &assigned_vkey.try_into().unwrap(),
            &assigned_proof.try_into().unwrap(),
            &assigned_public_inputs.try_into().unwrap(),
        );
        vec![]
    }
}

fn main() {
    run_cli::<Groth16ClientInput>();
}