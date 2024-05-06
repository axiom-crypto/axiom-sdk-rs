use std::{fmt::Debug, string, vec};

use axiom_circuit::subquery::groth16::{parse_groth16_input, Groth16Input};
use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomComputeInput, AxiomResult},
    cmd::run_cli,
    halo2_base::{gates::RangeInstructions, AssignedValue},
    subquery::groth16::assign_groth16_input,
    Fr,
};
use ethers::types::U256;
use serde_json::{json, Value};

#[AxiomComputeInput]
pub struct Groth16ClientInput {
    pub dummy: u64,
}

const MAX_PROOFS: usize = 16;

pub fn parse_worldcoin_input() -> Groth16Input<Fr> {
    let vk_string: String = include_str!("../data/worldcoin/vk.json").to_string();

    let input_json_str: &str = include_str!("../data/worldcoin/worldcoin_input.json");

    let input_json: Value = serde_json::from_str(input_json_str).unwrap();

    let public_input_json = json!([
        hex_value_to_bigint_str(&input_json["root"]),
        hex_value_to_bigint_str(&input_json["nullifier_hash"]),
        hex_value_to_bigint_str(&input_json["signal_hash"]),
        hex_value_to_bigint_str(&input_json["external_nullifier_hash"])
    ]);

    // root, nullifierHash, signalHash, externalNullifierHash

    let pub_string = serde_json::to_string(&public_input_json).unwrap();

    let proof = input_json["proof"].clone();

    let pf_string = json!({
        "pi_a": [hex_value_to_bigint_str(&proof[0][0]), hex_value_to_bigint_str(&proof[0][1]), "1"],
        "pi_b": [[hex_value_to_bigint_str(&proof[1][0][0]), hex_value_to_bigint_str(&proof[1][0][1])], [hex_value_to_bigint_str(&proof[1][1][0]), hex_value_to_bigint_str(&proof[1][1][1])], ["1", "0"]],
        "pi_c": [hex_value_to_bigint_str(&proof[2][0]), hex_value_to_bigint_str(&proof[2][1]), "1"],
        "protocol": "groth16",
        "curve": "bn128"
    })
    .to_string();

    let input = parse_groth16_input(vk_string, pf_string, pub_string);
    input
}

fn hex_value_to_bigint_str(value: &Value) -> String {
    println!("{}", value.as_str().unwrap().to_string());
    let bigint = U256::from_str_radix(&value.as_str().unwrap().to_string()[2..], 16)
        .expect("Failed to parse hex string");
    bigint.to_string()
}

impl AxiomComputeFn for Groth16ClientInput {
    fn compute(
        api: &mut AxiomAPI,
        _: Groth16ClientCircuitInput<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult> {
        let zero = api.ctx().load_zero();

        let mut return_vec: Vec<AxiomResult> = Vec::new();
        return_vec.reserve(MAX_PROOFS);

        for i in 1..=MAX_PROOFS {
            let input = parse_worldcoin_input();
            let assigned_input = assign_groth16_input(api, input);
            let nullifier_hash: AxiomResult = assigned_input.public_inputs[1].into();
            let signal_hash: AxiomResult = assigned_input.public_inputs[2].into();
            let verify = api.groth16_verify(assigned_input);
            let verify = api.from_hi_lo(verify);

            api.range.check_less_than(api.ctx(), zero, verify, 1);
            return_vec.push(nullifier_hash);
            return_vec.push(signal_hash)
        }

        return_vec
    }
}

fn main() {
    run_cli::<Groth16ClientInput>();
}
