use std::{fmt::Debug, str::FromStr};

use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomResult},
    cmd::run_cli,
    halo2_base::AssignedValue,
    subquery::{AccountField, HeaderField, TxField},
    AxiomComputeInput, Fr, HiLo,
};
use ethers::types::{Address, H256};

#[AxiomComputeInput]
pub struct KeccakInput {
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl AxiomComputeFn for KeccakInput {
    fn compute(
        api: &mut AxiomAPI,
        assigned_inputs: KeccakCircuitInput<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult> {
        let res = api.keccak_fix_len(vec![
            assigned_inputs.a,
            assigned_inputs.b,
            assigned_inputs.c,
        ]);
        vec![res.into()]
    }
}

fn main() {
    env_logger::init();
    run_cli::<KeccakInput>();
}
