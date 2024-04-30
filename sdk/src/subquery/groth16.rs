use axiom_circuit::{
    axiom_eth::{halo2_base::AssignedValue, halo2curves::bn256::Fr},
    subquery::groth16::Groth16Input,
};

use crate::api::AxiomAPI;

pub fn assign_groth16_input(
    api: &mut AxiomAPI,
    input: Groth16Input<Fr>,
) -> (
    Vec<AssignedValue<Fr>>,
    Vec<AssignedValue<Fr>>,
    Vec<AssignedValue<Fr>>,
) {
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
    (assigned_vkey, assigned_proof, assigned_public_inputs)
}
