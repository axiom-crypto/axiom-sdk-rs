use anyhow::Result;
use axiom_codec::types::native::AnySubquery;
use axiom_components::{
    ecdsa::{utils::verify_signature, ECDSAComponentInput, ECDSAComponentNativeInput},
    utils::flatten::InputFlatten,
};
use axiom_query::axiom_eth::{halo2_base::AssignedValue, Field};
use ethers::{
    providers::{JsonRpcClient, Provider},
    types::H256,
};

use super::caller::FetchSubquery;

impl<F: Field> FetchSubquery<F> for ECDSAComponentInput<AssignedValue<F>> {
    fn fetch<P: JsonRpcClient>(&self, _: &Provider<P>) -> Result<H256> {
        let flattened_subquery = self.flatten();
        let subquery_value: Vec<F> = flattened_subquery.iter().map(|v| *v.value()).collect();
        let unflattened_subquery = ECDSAComponentInput::unflatten(subquery_value).unwrap();
        let native_input: ECDSAComponentNativeInput = unflattened_subquery.into();
        let res = verify_signature(native_input)?;
        Ok(H256::from_low_u64_be(res as u64))
    }

    fn any_subquery(&self) -> AnySubquery {
        let flattened_subquery = self.flatten();
        let subquery_value: Vec<F> = flattened_subquery.iter().map(|v| *v.value()).collect();
        let unflattened_subquery = ECDSAComponentInput::unflatten(subquery_value).unwrap();
        let native_input: ECDSAComponentNativeInput = unflattened_subquery.into();
        AnySubquery::ECDSA(native_input)
    }

    fn flatten(&self) -> Vec<AssignedValue<F>> {
        self.flatten_vec()
    }
}
