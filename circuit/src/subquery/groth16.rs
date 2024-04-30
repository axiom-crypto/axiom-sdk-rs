use anyhow::Result;
use axiom_codec::types::native::AnySubquery;
pub use axiom_components::groth16::{MAX_PUBLIC_INPUTS, NUM_FE_PROOF, NUM_FE_VKEY};
use axiom_components::{
    groth16::{
        flatten_groth16_input,
        test::{default_groth16_input, parse_input, read_and_parse_input},
        types::{Groth16NativeInput, Groth16VerifierComponentInput, Groth16VerifierInput},
    },
    utils::flatten::InputFlatten,
};
use axiom_query::axiom_eth::{halo2_base::AssignedValue, halo2curves::bn256::Fr, Field};
use ethers::{
    providers::{JsonRpcClient, Provider},
    types::H256,
};

use super::caller::FetchSubquery;
pub struct Groth16Input<F: Field> {
    pub vkey_bytes: [F; NUM_FE_VKEY],
    pub proof_bytes: [F; NUM_FE_PROOF],
    pub public_inputs: [F; MAX_PUBLIC_INPUTS],
}

pub struct Groth16AssignedInput<F: Field> {
    pub vkey_bytes: [AssignedValue<F>; NUM_FE_VKEY],
    pub proof_bytes: [AssignedValue<F>; NUM_FE_PROOF],
    pub public_inputs: [AssignedValue<F>; MAX_PUBLIC_INPUTS],
}

impl<F: Field> FetchSubquery<F> for Groth16VerifierComponentInput<AssignedValue<F>> {
    fn fetch<P: JsonRpcClient>(&self, _: &Provider<P>) -> Result<H256> {
        unimplemented!()
    }

    fn any_subquery(&self) -> AnySubquery {
        let flattened_subquery = self.flatten();
        let subquery_value: Vec<F> = flattened_subquery.iter().map(|v| *v.value()).collect();
        let unflattened_subquery =
            Groth16VerifierComponentInput::unflatten(subquery_value).unwrap();
        let native_input: Groth16NativeInput = unflattened_subquery.into();
        AnySubquery::Groth16(native_input)
    }

    fn flatten(&self) -> Vec<AssignedValue<F>> {
        self.flatten_vec()
    }
}

pub fn flatten_groth16_input_into_separated_chunks<F: Field>(
    input: Groth16VerifierInput<F>,
) -> Groth16Input<F> {
    let mut packed_fe = flatten_groth16_input(input);
    // remove the final hash
    packed_fe.pop();
    let vkey = packed_fe[0..NUM_FE_VKEY].try_into().unwrap();
    let proof = packed_fe[NUM_FE_VKEY..NUM_FE_VKEY + NUM_FE_PROOF]
        .try_into()
        .unwrap();
    let public_inputs = packed_fe
        [NUM_FE_VKEY + NUM_FE_PROOF..NUM_FE_VKEY + NUM_FE_PROOF + MAX_PUBLIC_INPUTS]
        .try_into()
        .unwrap();
    Groth16Input {
        vkey_bytes: vkey,
        proof_bytes: proof,
        public_inputs,
    }
}

pub fn default_groth16_subquery_input() -> Groth16Input<Fr> {
    let input = default_groth16_input();
    flatten_groth16_input_into_separated_chunks(input)
}

pub fn read_and_parse_groth16_input(
    vk_path: String,
    pf_path: String,
    pub_path: String,
) -> Groth16Input<Fr> {
    let input = read_and_parse_input(vk_path, pf_path, pub_path);
    flatten_groth16_input_into_separated_chunks(input)
}

pub fn parse_groth16_input(
    vk_string: String,
    pf_string: String,
    pub_string: String,
) -> Groth16Input<Fr> {
    let input = parse_input(vk_string, pf_string, pub_string);
    flatten_groth16_input_into_separated_chunks(input)
}
