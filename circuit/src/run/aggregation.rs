use axiom_query::axiom_eth::{
    halo2_base::{
        gates::{circuit::CircuitBuilderStage, flex_gate::MultiPhaseThreadBreakPoints},
        utils::fs::gen_srs,
    },
    halo2_proofs::{
        dev::MockProver,
        plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    },
    halo2curves::bn256::G1Affine,
    snark_verifier_sdk::{halo2::gen_snark_shplonk, CircuitExt, Snark},
    utils::snark_verifier::AggregationCircuitParams,
};

use crate::{
    aggregation::create_aggregation_circuit,
    types::{AxiomCircuitParams, AxiomV2CircuitOutput, AxiomV2DataAndResults},
    utils::build_axiom_v2_compute_query,
};

pub fn agg_circuit_mock(agg_circuit_params: AggregationCircuitParams, snark: Snark) {
    let circuit = create_aggregation_circuit(agg_circuit_params, snark, CircuitBuilderStage::Mock);
    let instances = circuit.instances();
    MockProver::run(agg_circuit_params.degree, &circuit, instances)
        .unwrap()
        .assert_satisfied();
}

pub fn agg_circuit_keygen(
    agg_circuit_params: AggregationCircuitParams,
    snark: Snark,
) -> (
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
    MultiPhaseThreadBreakPoints,
) {
    let params = gen_srs(agg_circuit_params.degree);
    let circuit =
        create_aggregation_circuit(agg_circuit_params, snark, CircuitBuilderStage::Keygen);
    let vk = keygen_vk(&params, &circuit).expect("Failed to generate vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Failed to generate pk");
    let breakpoints = circuit.break_points();
    (vk, pk, breakpoints)
}

pub fn agg_circuit_prove(
    agg_circuit_params: AggregationCircuitParams,
    snark: Snark,
    pk: ProvingKey<G1Affine>,
    break_points: MultiPhaseThreadBreakPoints,
) -> Snark {
    let params = gen_srs(agg_circuit_params.degree);
    let circuit =
        create_aggregation_circuit(agg_circuit_params, snark, CircuitBuilderStage::Prover);
    let circuit = circuit.use_break_points(break_points);
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>)
}

pub fn agg_circuit_run(
    agg_circuit_params: AggregationCircuitParams,
    inner_snark: Snark,
    pk: ProvingKey<G1Affine>,
    break_points: MultiPhaseThreadBreakPoints,
    inner_output: AxiomV2DataAndResults,
    max_user_outputs: usize,
) -> AxiomV2CircuitOutput {
    let params = gen_srs(agg_circuit_params.degree);
    let circuit =
        create_aggregation_circuit(agg_circuit_params, inner_snark, CircuitBuilderStage::Prover);
    let circuit = circuit.use_break_points(break_points);
    let agg_circuit_params = circuit.builder.config_params.clone();
    let agg_snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
    let compute_query = build_axiom_v2_compute_query(
        agg_snark.clone(),
        AxiomCircuitParams::Base(agg_circuit_params),
        inner_output.clone(),
        max_user_outputs,
    );
    let output = AxiomV2CircuitOutput {
        compute_query,
        data: inner_output,
        snark: agg_snark,
    };
    output
}
