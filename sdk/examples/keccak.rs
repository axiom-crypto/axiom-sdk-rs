use std::fmt::Debug;

use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomComputeInput, AxiomResult},
    axiom_compute_prover_server,
    cmd::run_cli,
    halo2_base::AssignedValue,
    Fr,
};

#[AxiomComputeInput]
pub struct KeccakInput {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub len: u64,
}

impl AxiomComputeFn for KeccakInput {
    fn compute(
        api: &mut AxiomAPI,
        assigned_inputs: KeccakCircuitInput<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult> {
        let a = api.keccak_fix_len(vec![
            assigned_inputs.a,
            assigned_inputs.b,
            assigned_inputs.c,
        ]);
        let b = api.keccak_var_len(
            vec![assigned_inputs.a, assigned_inputs.b, assigned_inputs.c],
            assigned_inputs.len,
            3,
        );
        vec![a.into(), b.into()]
    }
}

fn main() {
    run_cli::<KeccakInput>();
}

// axiom_compute_prover_server!(KeccakInput);
