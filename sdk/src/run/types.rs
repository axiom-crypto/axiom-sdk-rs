use std::path::PathBuf;

use axiom_circuit::axiom_eth::utils::snark_verifier::AggregationCircuitParams;
pub use clap::Parser;
use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Subcommand, PartialEq)]
/// Circuit CLI commands
pub enum SnarkCmd {
    /// Run the mock prover
    Mock,
    /// Generate new proving & verifying keys
    Keygen,
    /// Generate an Axiom compute query
    Prove,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// Struct for specifying custom circuit parameters via JSON
pub struct RawCircuitParams<CoreParams> {
    pub k: usize,
    pub num_advice_per_phase: Vec<usize>,
    pub num_fixed: usize,
    pub num_lookup_advice_per_phase: Vec<usize>,
    pub lookup_bits: Option<usize>,
    pub num_rlc_columns: Option<usize>,
    pub keccak_rows_per_round: Option<usize>,
    pub max_outputs: Option<usize>,
    pub max_subqueries: Option<usize>,
    pub agg_params: Option<AggregationCircuitParams>,
    pub core_params: Option<CoreParams>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Command-line helper for building Axiom compute circuits
pub struct AxiomCircuitRunnerOptions {
    #[command(subcommand)]
    /// The command to run
    pub command: SnarkCmd,

    #[arg(
        short = 'k',
        long = "degree",
        help = "To determine the size of your circuit (12..25)"
    )]
    /// The degree of the circuit
    pub degree: Option<u32>,

    #[arg(short = 'p', long = "provider", help = "JSON RPC provider URI")]
    /// The JSON RPC provider URI
    pub provider: Option<String>,

    #[arg(short, long = "input", help = "JSON inputs to feed into your circuit")]
    /// The JSON inputs to feed into your circuit
    pub input_path: Option<PathBuf>,

    #[arg(
        short,
        long = "name",
        help = "Name of the output metadata file",
        default_value = "circuit"
    )]
    /// Name of the output metadata file
    pub name: String,

    #[arg(
        short,
        long = "data-path",
        help = "For saving build artifacts",
        default_value = "data"
    )]
    /// The path to save build artifacts
    pub data_path: PathBuf,

    //Advanced options
    #[arg(
        short = 'c',
        long = "config",
        help = "For specifying custom circuit parameters"
    )]
    /// The path to a custom circuit configuration
    pub config: Option<PathBuf>,

    #[arg(long = "srs", help = "For specifying custom KZG params directory")]
    /// The path to the KZG params folder
    pub srs: Option<PathBuf>,

    #[arg(
        long = "aggregate",
        help = "Whether to aggregate the output (defaults to false)",
        action
    )]
    /// Whether to aggregate the output
    pub should_aggregate: bool,

    #[arg(
        long = "auto-config-aggregation",
        help = "Whether to aggregate the output (defaults to false)",
        action
    )]
    /// Whether to auto calculate the aggregation params
    pub should_auto_config_aggregation_circuit: bool,
}
