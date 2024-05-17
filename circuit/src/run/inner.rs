use axiom_codec::types::native::AxiomV2ComputeQuery;
use axiom_query::axiom_eth::{
    halo2_base::utils::fs::gen_srs,
    halo2_proofs::{
        dev::MockProver,
        plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    },
    halo2curves::bn256::{Fr, G1Affine},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, Snark},
    utils::keccak::decorator::RlcKeccakCircuitParams,
};
use ethers::{
    providers::{JsonRpcClient, Provider},
    types::Bytes,
};

use crate::{
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{AxiomCircuitParams, AxiomCircuitPinning, AxiomV2CircuitOutput, AxiomV2DataAndResults},
    utils::build_axiom_v2_compute_query,
};

pub fn mock<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    provider: Provider<P>,
    raw_circuit_params: AxiomCircuitParams,
    inputs: Option<S::InputValue>,
) {
    let circuit_params = RlcKeccakCircuitParams::from(raw_circuit_params.clone());
    let k = circuit_params.k();
    let mut runner = AxiomCircuit::<_, _, S>::new(provider, raw_circuit_params).use_inputs(inputs);
    if circuit_params.keccak_rows_per_round > 0 {
        runner.calculate_params();
    }
    let instances = runner.instances();
    MockProver::run(k as u32, &runner, instances)
        .unwrap()
        .assert_satisfied();
}

pub fn keygen<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    provider: Provider<P>,
    raw_circuit_params: AxiomCircuitParams,
    inputs: Option<S::InputValue>,
) -> (
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
    AxiomCircuitPinning,
) {
    let circuit_params = RlcKeccakCircuitParams::from(raw_circuit_params.clone());
    let params = gen_srs(circuit_params.k() as u32);
    let mut runner = AxiomCircuit::<_, _, S>::new(provider, raw_circuit_params).use_inputs(inputs);
    if circuit_params.keccak_rows_per_round > 0 {
        runner.calculate_params();
    }
    let vk = keygen_vk(&params, &runner).expect("Failed to generate vk");
    let pinning = runner.pinning();
    let pk = keygen_pk(&params, vk.clone(), &runner).expect("Failed to generate pk");
    (vk, pk, pinning)
}

pub fn prove<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    provider: Provider<P>,
    pinning: AxiomCircuitPinning,
    inputs: Option<S::InputValue>,
    pk: ProvingKey<G1Affine>,
) -> Snark {
    let circuit_params = RlcKeccakCircuitParams::from(pinning.params.clone());
    let params = gen_srs(circuit_params.k() as u32);
    let mut runner = AxiomCircuit::<_, _, S>::prover(provider, pinning).use_inputs(inputs);
    if circuit_params.keccak_rows_per_round > 0 {
        runner.calculate_params();
    }
    gen_snark_shplonk(&params, &pk, runner, None::<&str>)
}

pub fn run<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    provider: Provider<P>,
    pinning: AxiomCircuitPinning,
    inputs: Option<S::InputValue>,
    pk: ProvingKey<G1Affine>,
) -> AxiomV2CircuitOutput {
    let circuit_params = RlcKeccakCircuitParams::from(pinning.params.clone());
    let k = circuit_params.k();
    let params = gen_srs(k as u32);
    let mut runner = AxiomCircuit::<_, _, S>::prover(provider, pinning.clone()).use_inputs(inputs);
    let output = runner.scaffold_output();
    if circuit_params.keccak_rows_per_round > 0 {
        runner.calculate_params();
    }
    let snark = gen_snark_shplonk(&params, &pk, runner, None::<&str>);
    let raw_circuit_params = pinning.params.clone();
    let compute_query = match raw_circuit_params {
        AxiomCircuitParams::Base(_) => {
            build_axiom_v2_compute_query(snark.clone(), raw_circuit_params, output.clone())
        }
        AxiomCircuitParams::Keccak(_) => {
            log::warn!("Circuit with keccak must be aggregated before submitting on chain");
            AxiomV2ComputeQuery {
                k: k as u8,
                result_len: output.compute_results.len() as u16,
                vkey: vec![],
                compute_proof: Bytes::default(),
            }
        }
        AxiomCircuitParams::Rlc(_) => {
            log::warn!("Circuit with RLC must be aggregated before submitting on chain");
            build_axiom_v2_compute_query(snark.clone(), raw_circuit_params, output.clone())
        }
    };
    let output = AxiomV2CircuitOutput {
        compute_query,
        data: output,
        snark,
    };
    output
}

pub fn witness_gen<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    provider: Provider<P>,
    pinning: AxiomCircuitPinning,
    inputs: Option<S::InputValue>,
) -> AxiomV2DataAndResults {
    let runner = AxiomCircuit::<_, _, S>::prover(provider, pinning.clone()).use_inputs(inputs);
    let output = runner.scaffold_output();
    output
}
