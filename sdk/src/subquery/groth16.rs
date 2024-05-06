use axiom_circuit::{
    axiom_eth::{halo2_base::AssignedValue, halo2curves::bn256::Fr},
    subquery::groth16::{Groth16AssignedInput, Groth16Input},
};

use crate::api::AxiomAPI;

pub fn assign_groth16_input(
    api: &mut AxiomAPI,
    input: Groth16Input<Fr>,
) -> Groth16AssignedInput<Fr> {
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
    Groth16AssignedInput {
        vkey_bytes: assigned_vkey.try_into().unwrap(),
        proof_bytes: assigned_proof.try_into().unwrap(),
        public_inputs: assigned_public_inputs.try_into().unwrap(),
    }
}

pub fn assign_groth16_input_with_known_vk(
    api: &mut AxiomAPI,
    assigned_vk: Vec<AssignedValue<Fr>>,
    proof_bytes: Vec<Fr>,
    pi: Vec<Fr>,
) -> Groth16AssignedInput<Fr> {
    let assigned_proof = proof_bytes
        .iter()
        .map(|v| api.ctx().load_witness(*v))
        .collect::<Vec<_>>();
    let assigned_public_inputs = pi
        .iter()
        .map(|v| api.ctx().load_witness(*v))
        .collect::<Vec<_>>();
    Groth16AssignedInput {
        vkey_bytes: assigned_vk,
        proof_bytes: assigned_proof.try_into().unwrap(),
        public_inputs: assigned_public_inputs.try_into().unwrap(),
    }
}
