use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axiom_circuit::{
    axiom_eth::{
        halo2_proofs::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
        halo2curves::bn256::{Bn256, G1Affine},
    },
    types::{
        AggregationCircuitPinning, AxiomCircuitPinning, AxiomV2CircuitOutput, AxiomV2DataAndResults,
    },
};
use clap::Parser;
use ethers::providers::{Http, Provider};
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct AxiomComputeCircuitCtx<CoreParams> {
    pub pk: ProvingKey<G1Affine>,
    pub pinning: AxiomCircuitPinning<CoreParams>,
    pub params: ParamsKZG<Bn256>,
}

#[derive(Clone, Debug)]
pub struct AggregationCircuitCtx<CoreParams> {
    pub pk: ProvingKey<G1Affine>,
    pub pinning: AggregationCircuitPinning<CoreParams>,
    pub params: ParamsKZG<Bn256>,
}

#[derive(Clone, Debug)]
pub struct AxiomComputeCtx<CoreParams> {
    pub child: AxiomComputeCircuitCtx<CoreParams>,
    pub agg: Option<AggregationCircuitCtx<CoreParams>>,
    pub provider: Provider<Http>,
}

#[derive(Clone, Debug, Serialize)]
pub enum AxiomComputeJobStatus {
    Received,
    DataQueryReady,
    InnerOutputReady,
    OutputReady,
    Error,
}

#[derive(Clone, Debug, Default)]
pub struct AxiomComputeManager {
    pub job_queue: Arc<Mutex<Vec<u64>>>,
    pub inputs: Arc<Mutex<HashMap<u64, String>>>,
    pub job_status: Arc<Mutex<HashMap<u64, AxiomComputeJobStatus>>>,
    pub data_query: Arc<Mutex<HashMap<u64, AxiomV2DataAndResults>>>,
    pub outputs: Arc<Mutex<HashMap<u64, AxiomV2CircuitOutput>>>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct AxiomComputeServerCmd {
    #[arg(
        short,
        long = "data-path",
        help = "For loading build artifacts",
        default_value = "data"
    )]
    /// The path to load build artifacts from
    pub data_path: String,

    #[arg(
        short,
        long = "name",
        help = "Name of the circuit metadata file",
        default_value = "circuit"
    )]
    /// Name of the circuit metadata file
    pub circuit_name: String,

    #[arg(short = 'p', long = "provider", help = "JSON RPC provider URI")]
    /// The JSON RPC provider URI
    pub provider: Option<String>,

    #[arg(
        long = "srs",
        help = "For specifying custom KZG params directory (defaults to `params`)",
        default_value = "params"
    )]
    /// The path to the KZG params folder
    pub srs_path: String,
}
