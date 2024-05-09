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
        all_subqueries_call, ecdsa_call, groth16_call, header_call, mapping_call, receipt_call,
        storage_call, tx_call,
    },
};
use crate::{
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    subquery::caller::SubqueryCaller,
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

base_test_struct!(AccountTest, account_call);
base_test_struct!(HeaderTest, header_call);
base_test_struct!(ReceiptTest, receipt_call);
base_test_struct!(StorageTest, storage_call);
base_test_struct!(MappingTest, mapping_call);
base_test_struct!(TxTest, tx_call);
base_test_struct!(AllSubqueryTest, all_subqueries_call);
base_test_struct!(EcdsaTest, ecdsa_call);
base_test_struct!(Groth16Test, groth16_call);

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
    let params = get_base_test_params();
    let client = get_provider();
    let runner = AxiomCircuit::<_, _, S>::new(client, params);
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
