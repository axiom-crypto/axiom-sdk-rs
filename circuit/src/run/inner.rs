use axiom_codec::types::native::AxiomV2ComputeQuery;
use axiom_query::axiom_eth::{
    halo2_proofs::{
        dev::MockProver,
        plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
        poly::kzg::commitment::ParamsKZG,
    },
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, Snark},
    utils::keccak::decorator::RlcKeccakCircuitParams,
};
use ethers::{providers::JsonRpcClient, types::Bytes};

use crate::{
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{AxiomCircuitParams, AxiomCircuitPinning, AxiomV2CircuitOutput},
    utils::{
        build_axiom_v2_compute_query, check_compute_proof_format, check_compute_query_format,
        verify_snark, DK,
    },
};

pub fn mock<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    circuit: &mut AxiomCircuit<Fr, P, S>,
) {
    let raw_circuit_params = circuit.params();
    let circuit_params = RlcKeccakCircuitParams::from(raw_circuit_params.clone());
    let k = circuit_params.k();
    if circuit_params.keccak_rows_per_round > 0 {
        circuit.calculate_params();
    }
    let instances = circuit.instances();
    MockProver::run(k as u32, circuit, instances)
        .unwrap()
        .assert_satisfied();
}

pub fn keygen<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    circuit: &mut AxiomCircuit<Fr, P, S>,
    params: &ParamsKZG<Bn256>,
) -> (
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
    AxiomCircuitPinning,
) {
    let raw_circuit_params = circuit.params();
    let circuit_params = RlcKeccakCircuitParams::from(raw_circuit_params.clone());
    if circuit_params.keccak_rows_per_round > 0 {
        circuit.calculate_params();
    }
    let vk = keygen_vk(params, circuit).expect("Failed to generate vk");
    let pinning = circuit.pinning();
    let pk = keygen_pk(params, vk.clone(), circuit).expect("Failed to generate pk");
    (vk, pk, pinning)
}

pub fn prove<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    circuit: &mut AxiomCircuit<Fr, P, S>,
    pk: ProvingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
) -> Snark {
    let raw_circuit_params = circuit.params();
    let circuit_params = RlcKeccakCircuitParams::from(raw_circuit_params.clone());
    if circuit_params.keccak_rows_per_round > 0 {
        circuit.calculate_params();
    }
    gen_snark_shplonk(params, &pk, circuit.clone(), None::<&str>)
}

pub fn run<P: JsonRpcClient + Clone, S: AxiomCircuitScaffold<P, Fr>>(
    circuit: &mut AxiomCircuit<Fr, P, S>,
    pk: &ProvingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
) -> AxiomV2CircuitOutput {
    let raw_circuit_params = circuit.params();
    let circuit_params = RlcKeccakCircuitParams::from(raw_circuit_params.clone());
    let k = circuit_params.k();
    let output = circuit.scaffold_output();
    if circuit_params.keccak_rows_per_round > 0 {
        circuit.calculate_params();
    }
    let max_user_outputs = circuit.max_user_outputs;
    let snark = gen_snark_shplonk(params, pk, circuit.clone(), None::<&str>);
    let compute_query = match raw_circuit_params {
        AxiomCircuitParams::Base(_) => build_axiom_v2_compute_query(
            snark.clone(),
            raw_circuit_params.clone(),
            output.clone(),
            max_user_outputs,
        ),
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
            build_axiom_v2_compute_query(
                snark.clone(),
                raw_circuit_params.clone(),
                output.clone(),
                max_user_outputs,
            )
        }
    };

    let circuit_output = AxiomV2CircuitOutput {
        compute_query,
        data: output,
        snark,
    };

    let vk = pk.get_vk();
    if let AxiomCircuitParams::Keccak(_) = raw_circuit_params {
    } else {
        check_compute_proof_format(circuit_output.clone(), false);
        check_compute_query_format(
            circuit_output.clone(),
            raw_circuit_params,
            vk.clone(),
            circuit.max_user_outputs,
        );
        verify_snark(&DK, &circuit_output.snark)
            .expect("Client snark failed to verify. Make sure you are using the right KZG params.");
    }

    circuit_output
}
