use axiom_query::axiom_eth::{
    halo2_base::gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        dev::MockProver,
        plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
        poly::kzg::commitment::ParamsKZG,
    },
    halo2curves::bn256::{Bn256, G1Affine},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, CircuitExt, Snark},
    utils::snark_verifier::AggregationCircuitParams,
};

use crate::{
    aggregation::create_aggregation_circuit,
    types::{
        AggregationCircuitPinning, AxiomCircuitParams, AxiomCircuitPinning, AxiomV2CircuitOutput,
    },
    utils::{
        build_axiom_v2_compute_query, check_compute_proof_format, check_compute_query_format,
        get_query_schema_from_compute_query, verify_snark, DK,
    },
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
    child_pinning: AxiomCircuitPinning,
    params: &ParamsKZG<Bn256>,
    should_calculate_params: bool,
) -> (
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
    AggregationCircuitPinning,
) {
    let mut circuit =
        create_aggregation_circuit(agg_circuit_params, snark, CircuitBuilderStage::Keygen);
    let mut calculated_params = agg_circuit_params;
    if should_calculate_params {
        calculated_params = circuit.calculate_params(Some(100));
    }
    let vk = keygen_vk(params, &circuit).expect("Failed to generate vk");
    let pk = keygen_pk(params, vk.clone(), &circuit).expect("Failed to generate pk");
    let breakpoints = circuit.break_points();
    let pinning = AggregationCircuitPinning {
        child_pinning,
        break_points: breakpoints,
        params: calculated_params,
    };
    (vk, pk, pinning)
}

pub fn agg_circuit_prove(
    agg_circuit_pinning: AggregationCircuitPinning,
    snark: Snark,
    pk: ProvingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
) -> Snark {
    let circuit = create_aggregation_circuit(
        agg_circuit_pinning.params,
        snark,
        CircuitBuilderStage::Prover,
    );
    let circuit = circuit.use_break_points(agg_circuit_pinning.break_points);
    gen_snark_shplonk(params, &pk, circuit, None::<&str>)
}

pub fn agg_circuit_run(
    agg_circuit_pinning: AggregationCircuitPinning,
    inner_output: AxiomV2CircuitOutput,
    pk: &ProvingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
) -> AxiomV2CircuitOutput {
    let circuit = create_aggregation_circuit(
        agg_circuit_pinning.params,
        inner_output.snark,
        CircuitBuilderStage::Prover,
    );
    let circuit = circuit.use_break_points(agg_circuit_pinning.break_points);
    let agg_circuit_params = circuit.builder.config_params.clone();
    let agg_snark = gen_snark_shplonk(params, pk, circuit, None::<&str>);
    let compute_query = build_axiom_v2_compute_query(
        agg_snark.clone(),
        AxiomCircuitParams::Base(agg_circuit_params.clone()),
        inner_output.data.clone(),
        agg_circuit_pinning.child_pinning.max_user_outputs,
    );

    let query_schema = get_query_schema_from_compute_query(compute_query.clone()).unwrap();

    let circuit_output = AxiomV2CircuitOutput {
        compute_query,
        data: inner_output.data,
        snark: agg_snark,
        query_schema,
    };

    let vk = pk.get_vk();
    check_compute_proof_format(circuit_output.clone(), true);
    check_compute_query_format(
        circuit_output.clone(),
        AxiomCircuitParams::Base(agg_circuit_params),
        vk.clone(),
        agg_circuit_pinning.child_pinning.max_user_outputs,
    );
    verify_snark(&DK, &circuit_output.snark)
        .expect("Client snark failed to verify. Make sure you are using the right KZG params.");

    circuit_output
}
