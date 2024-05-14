use std::collections::HashMap;

use axiom_codec::types::native::AxiomV2ComputeQuery;
use axiom_query::{
    axiom_eth::{
        halo2_base::gates::{
            circuit::{BaseCircuitParams, BaseConfig},
            flex_gate::MultiPhaseThreadBreakPoints,
        },
        rlc::{
            circuit::{RlcCircuitParams, RlcConfig},
            virtual_region::RlcThreadBreakPoints,
        },
        snark_verifier_sdk::Snark,
        utils::{
            keccak::decorator::{RlcKeccakCircuitParams, RlcKeccakConfig},
            snark_verifier::AggregationCircuitParams,
        },
        Field,
    },
    utils::client_circuit::metadata::AxiomV2CircuitMetadata,
};
use ethers::types::H256;
use serde::{Deserialize, Serialize};

use crate::subquery::types::Subquery;

#[derive(Clone, Debug)]
pub enum AxiomCircuitConfig<F: Field> {
    Base(BaseConfig<F>),
    Rlc(RlcConfig<F>),
    Keccak(RlcKeccakConfig<F>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AxiomCircuitParams {
    Base(BaseCircuitParams),
    Rlc(RlcCircuitParams),
    Keccak(RlcKeccakCircuitParams),
}

impl Default for AxiomCircuitParams {
    fn default() -> Self {
        Self::Base(BaseCircuitParams::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxiomCircuitPinning<CoreParams> {
    pub core_params: CoreParams,
    pub params: AxiomCircuitParams,
    pub break_points: RlcThreadBreakPoints,
    pub max_user_outputs: usize,
    pub max_user_subqueries: usize,
    pub max_groth16_pi: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationCircuitPinning<CoreParams> {
    pub child_pinning: AxiomCircuitPinning<CoreParams>,
    pub break_points: MultiPhaseThreadBreakPoints,
    pub params: AggregationCircuitParams,
}

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AxiomV2DataAndResults {
    pub data_query: Vec<Subquery>,
    pub compute_results: Vec<H256>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AxiomV2CircuitOutput {
    pub compute_query: AxiomV2ComputeQuery,
    #[serde(flatten)]
    pub data: AxiomV2DataAndResults,
    pub query_schema: H256,
    #[serde(skip_serializing)]
    pub snark: Snark,
}

impl From<AxiomCircuitParams> for RlcKeccakCircuitParams {
    fn from(value: AxiomCircuitParams) -> Self {
        match value {
            AxiomCircuitParams::Base(params) => RlcKeccakCircuitParams {
                keccak_rows_per_round: 0,
                rlc: RlcCircuitParams {
                    base: params,
                    num_rlc_columns: 0,
                },
            },
            AxiomCircuitParams::Rlc(params) => RlcKeccakCircuitParams {
                keccak_rows_per_round: 0,
                rlc: params,
            },
            AxiomCircuitParams::Keccak(params) => params,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AxiomClientCircuitMetadata {
    pub metadata: AxiomV2CircuitMetadata,
    pub circuit_id: String,
    pub data_query_size: HashMap<usize, usize>,
    pub agg_circuit_id: Option<String>,
    pub max_user_outputs: usize,
    pub max_user_subqueries: usize,
    pub preprocessed_len: usize,
    pub query_schema: H256,
}
