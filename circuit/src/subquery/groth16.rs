use anyhow::Result;
use axiom_codec::types::native::AnySubquery;
pub use axiom_components::groth16::NUM_FE_PROOF;
use axiom_components::{
    groth16::{
        get_groth16_consts_from_max_pi,
        test::{default_groth16_input, flatten_groth16_input, parse_input, read_and_parse_input},
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
    pub vkey_bytes: Vec<F>,
    pub proof_bytes: Vec<F>,
    pub public_inputs: Vec<F>,
}

pub struct Groth16AssignedInput<F: Field> {
    pub vkey_bytes: Vec<AssignedValue<F>>,
    pub proof_bytes: Vec<AssignedValue<F>>,
    pub public_inputs: Vec<AssignedValue<F>>,
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
    max_pi: usize,
) -> Groth16Input<F> {
    let constants = get_groth16_consts_from_max_pi(max_pi);
    let mut packed_fe = flatten_groth16_input(input, max_pi);
    // remove the final hash
    packed_fe.pop();
    let vkey = packed_fe[0..constants.num_fe_vkey].try_into().unwrap();
    let proof = packed_fe[constants.num_fe_vkey..constants.num_fe_vkey + NUM_FE_PROOF]
        .try_into()
        .unwrap();
    let public_inputs = packed_fe[constants.num_fe_vkey + NUM_FE_PROOF
        ..constants.num_fe_vkey + NUM_FE_PROOF + constants.max_pi]
        .try_into()
        .unwrap();
    Groth16Input {
        vkey_bytes: vkey,
        proof_bytes: proof,
        public_inputs,
    }
}

pub fn default_groth16_subquery_input(max_pi: usize) -> Groth16Input<Fr> {
    let input = default_groth16_input(max_pi);
    flatten_groth16_input_into_separated_chunks(input, max_pi)
}

pub fn read_and_parse_groth16_input(
    vk_path: String,
    pf_path: String,
    pub_path: String,
    max_pi: usize,
) -> Groth16Input<Fr> {
    let input = read_and_parse_input(vk_path, pf_path, pub_path, max_pi);
    flatten_groth16_input_into_separated_chunks(input, max_pi)
}

pub fn parse_groth16_input(
    vk_string: String,
    pf_string: String,
    pub_string: String,
    max_pi: usize,
) -> Groth16Input<Fr> {
    let input = parse_input(vk_string, pf_string, pub_string, max_pi);
    flatten_groth16_input_into_separated_chunks(input, max_pi)
}
