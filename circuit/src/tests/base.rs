use std::sync::{Arc, Mutex};

use axiom_codec::HiLo;
use axiom_query::axiom_eth::{
    halo2_base::{
        gates::{circuit::BaseCircuitParams, RangeChip},
        AssignedValue,
    },
    halo2curves::bn256::Fr,
    rlc::circuit::builder::RlcCircuitBuilder,
};
use ethers::providers::{Http, JsonRpcClient};
use test_case::test_case;

use super::{
    shared_tests::check_compute_proof_and_query_format,
    utils::{
        all_subqueries_call, ecdsa_call, groth16_call, groth16_call_5_pi, header_call,
        mapping_call, receipt_call, storage_call, tx_call,
    },
};
use crate::{
    constants::DEFAULT_MAX_GROTH16_PI,
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    subquery::{caller::SubqueryCaller, groth16::default_groth16_subquery_input},
    tests::{
        shared_tests::{mock_test, single_instance_test},
        utils::{account_call, EmptyCircuitInput},
    },
    types::AxiomCircuitParams,
    utils::get_provider,
};

macro_rules! base_test_struct {
    ($struct_name:ident, $subquery_call:ident) => {
        #[derive(Debug, Clone, Default)]
        struct $struct_name;
        impl<P: JsonRpcClient> AxiomCircuitScaffold<P, Fr> for $struct_name {
            type InputValue = EmptyCircuitInput<Fr>;
            type InputWitness = EmptyCircuitInput<AssignedValue<Fr>>;

            fn virtual_assign_phase0(
                builder: &mut RlcCircuitBuilder<Fr>,
                _range: &RangeChip<Fr>,
                subquery_caller: Arc<Mutex<SubqueryCaller<P, Fr>>>,
                _callback: &mut Vec<HiLo<AssignedValue<Fr>>>,
                _inputs: Self::InputWitness,
                _core_params: Self::CoreParams,
            ) {
                $subquery_call(builder, subquery_caller);
            }
        }
    };
}

fn get_base_test_params() -> AxiomCircuitParams {
    let params = BaseCircuitParams {
        k: 12,
        num_advice_per_phase: vec![4],
        num_lookup_advice_per_phase: vec![1],
        num_fixed: 1,
        num_instance_columns: 1,
        lookup_bits: Some(11),
    };
    AxiomCircuitParams::Base(params)
}

const GROTH16_TEST_OUTPUT: &str = include_str!("./data/groth16_test_output.json");
const GROTH16_TEST_INPUT: &str = include_str!("./data/groth16_test_input.json");

base_test_struct!(AccountTest, account_call);
base_test_struct!(HeaderTest, header_call);
base_test_struct!(ReceiptTest, receipt_call);
base_test_struct!(StorageTest, storage_call);
base_test_struct!(MappingTest, mapping_call);
base_test_struct!(TxTest, tx_call);
base_test_struct!(AllSubqueryTest, all_subqueries_call);
base_test_struct!(EcdsaTest, ecdsa_call);
base_test_struct!(Groth16Test, groth16_call);
base_test_struct!(Groth16Test5Pi, groth16_call_5_pi);

// #[test_case(AccountTest)]
// #[test_case(HeaderTest)]
// #[test_case(ReceiptTest)]
// #[test_case(StorageTest)]
// #[test_case(MappingTest)]
// #[test_case(TxTest)]
#[test_case(AllSubqueryTest)]
pub fn mock<S: AxiomCircuitScaffold<Http, Fr>>(_circuit: S) {
    let params = get_base_test_params();
    mock_test::<S>(params);
}

#[test_case(AccountTest, 1)]
#[test_case(HeaderTest, 1)]
#[test_case(ReceiptTest, 1)]
#[test_case(StorageTest, 1)]
#[test_case(MappingTest, 1)]
#[test_case(TxTest, 1)]
#[test_case(EcdsaTest, 1)]
#[test_case(Groth16Test, 3)]
pub fn test_single_subquery_instances<S: AxiomCircuitScaffold<Http, Fr>>(
    _circuit: S,
    num_subqueries: usize,
) {
    test_single_subquery_instances_with_max_groth16_pi::<S>(
        _circuit,
        num_subqueries,
        DEFAULT_MAX_GROTH16_PI,
    );
}

#[test_case(Groth16Test5Pi, 4, 5)]
pub fn test_single_subquery_instances_with_max_groth16_pi<S: AxiomCircuitScaffold<Http, Fr>>(
    _circuit: S,
    num_subqueries: usize,
    max_groth16_pi: usize,
) {
    let params = get_base_test_params();
    let client = get_provider();
    let runner = AxiomCircuit::<_, _, S>::new(client, params).use_max_groth16_pi(max_groth16_pi);
    let instances = runner.instances();
    let num_user_output_fe = runner.output_num_instances();
    let subquery_fe = runner.subquery_num_instances();
    let results = runner.scaffold_output();
    single_instance_test(
        instances,
        num_user_output_fe,
        subquery_fe,
        results,
        None,
        Some(num_subqueries),
    );
}

// #[test_case(AccountTest)]
// #[test_case(HeaderTest)]
// #[test_case(ReceiptTest)]
// #[test_case(StorageTest)]
// #[test_case(MappingTest)]
// #[test_case(TxTest)]
#[test_case(AllSubqueryTest)]
pub fn test_compute_query<S: AxiomCircuitScaffold<Http, Fr>>(_circuit: S) {
    let params = get_base_test_params();
    check_compute_proof_and_query_format::<S>(params, false);
}

#[test_case(Groth16Test)]
pub fn test_groth16_output<S: AxiomCircuitScaffold<Http, Fr>>(_circuit: S) {
    let params = get_base_test_params();
    let client = get_provider();
    let runner = AxiomCircuit::<_, _, S>::new(client.clone(), params.clone());
    let results = runner.scaffold_output();
    let test_output: serde_json::Value = serde_json::from_str(GROTH16_TEST_OUTPUT)
        .expect("Failed to parse Groth16 test input data as JSON");
    let results_json: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&results).unwrap())
            .expect("Failed to parse Groth16 test input data as JSON");
    assert_eq!(results_json, test_output);
}

#[test]
pub fn test_groth16_input() {
    let input = default_groth16_subquery_input(4);
    let serialized_input =
        serde_json::to_string(&input).expect("Failed to serialize Groth16 input");
    let input: serde_json::Value = serde_json::from_str(&serialized_input)
        .expect("Failed to parse Groth16 input data as JSON");
    let groth16_test_input: serde_json::Value = serde_json::from_str(GROTH16_TEST_INPUT)
        .expect("Failed to parse Groth16 test input data as JSON");

    assert_eq!(input, groth16_test_input);
}
