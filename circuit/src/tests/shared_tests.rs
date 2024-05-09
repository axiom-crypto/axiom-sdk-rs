use axiom_codec::{
    constants::USER_MAX_OUTPUTS,
    types::field_elements::{FieldSubqueryResult, SUBQUERY_RESULT_LEN},
};
use axiom_query::axiom_eth::{
    halo2_base::utils::fs::gen_srs,
    halo2curves::bn256::{Fr, G1Affine},
    snark_verifier::pcs::{kzg::LimbsEncoding, AccumulatorEncoding},
    snark_verifier_sdk::{NativeLoader, Snark, BITS, LIMBS},
    utils::snark_verifier::NUM_FE_ACCUMULATOR,
};
use ethers::providers::Http;
use itertools::Itertools;

use crate::{
    run::inner::{keygen, mock, run},
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{AxiomCircuitParams, AxiomV2DataAndResults},
    utils::{check_compute_proof_format, check_compute_query_format, get_provider},
};

pub fn mock_test<S: AxiomCircuitScaffold<Http, Fr>>(params: AxiomCircuitParams) {
    let client = get_provider();
    let mut runner = AxiomCircuit::<_, _, S>::new(client, params);
    mock::<_, S>(&mut runner);
}

pub fn single_instance_test(
    instances: Vec<Vec<Fr>>,
    num_user_output_fe: usize,
    num_subquery_fe: usize,
    results: AxiomV2DataAndResults,
    inner_snark: Option<Snark>,
    num_subqueries: Option<usize>,
) {
    let num_subqueries = num_subqueries.unwrap_or(1);
    //check that there's only one instance column
    assert_eq!(instances.len(), 1);
    let mut instances = instances.get(0).unwrap().clone();
    if let Some(snark) = inner_snark {
        assert_eq!(
            instances.len(),
            NUM_FE_ACCUMULATOR + num_user_output_fe + num_subquery_fe
        );
        let inner_instances = snark.instances.get(0).unwrap().clone();
        <LimbsEncoding<LIMBS, BITS> as AccumulatorEncoding<G1Affine, NativeLoader>>::from_repr(
            &instances[..NUM_FE_ACCUMULATOR].iter().collect_vec(),
        )
        .unwrap();
        instances.drain(0..NUM_FE_ACCUMULATOR);
        assert_eq!(instances, inner_instances);
    }
    //check that number of instances is equal to number of user output field elements + number of subquery field elements
    assert_eq!(instances.len(), num_user_output_fe + num_subquery_fe);
    //check that user output field elements are all zero (as we don't add any in these tests)
    assert_eq!(
        &instances[0..num_user_output_fe],
        &vec![Fr::from(0); num_user_output_fe]
    );
    //check that there's only `num_subqueries` subqueries (defaults to 1)
    assert_eq!(results.data_query.len(), num_subqueries);
    let subquery = FieldSubqueryResult::<Fr>::from(results.data_query.get(0).unwrap().clone());
    //check the instances that correspond to single data subquery
    assert_eq!(
        subquery.to_fixed_array(),
        &instances[num_user_output_fe..num_user_output_fe + SUBQUERY_RESULT_LEN]
    );
    //check that remaining instances are zero
    assert_eq!(
        &instances[num_user_output_fe + SUBQUERY_RESULT_LEN * num_subqueries..],
        &vec![Fr::from(0); num_subquery_fe - SUBQUERY_RESULT_LEN * num_subqueries]
    );
}

pub fn check_compute_proof_and_query_format<S: AxiomCircuitScaffold<Http, Fr>>(
    params: AxiomCircuitParams,
    is_aggregation: bool,
) {
    let client = get_provider();
    let mut runner = AxiomCircuit::<_, _, S>::new(client.clone(), params.clone());
    let kzg_params = gen_srs(runner.k() as u32);
    let (vk, pk, pinning) = keygen::<_, S>(&mut runner, &kzg_params);
    let runner = AxiomCircuit::<_, _, S>::prover(client, pinning);
    let output = run::<_, S>(runner, &pk, &kzg_params);
    check_compute_proof_format(output.clone(), is_aggregation);
    check_compute_query_format(output, params, vk, USER_MAX_OUTPUTS);
}
