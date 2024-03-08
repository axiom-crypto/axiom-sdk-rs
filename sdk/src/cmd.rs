use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    path::PathBuf,
};

use axiom_circuit::{
    axiom_codec::constants::{USER_MAX_OUTPUTS, USER_MAX_SUBQUERIES},
    axiom_eth::{
        halo2_base::{gates::circuit::BaseCircuitParams, AssignedValue},
        rlc::circuit::RlcCircuitParams,
        utils::{
            build_utils::keygen::read_srs_from_dir, keccak::decorator::RlcKeccakCircuitParams,
        },
    },
    run::inner::{keygen, mock, run},
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::AxiomCircuitParams,
};
pub use clap::Parser;
use clap::Subcommand;
use ethers::providers::{Http, Provider};
use log::warn;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    compute::{AxiomCompute, AxiomComputeFn},
    utils::io::{read_pinning, read_pk, write_output, write_pinning, write_pk},
    Fr,
};

#[derive(Clone, Copy, Debug, Subcommand)]
/// Circuit CLI commands
pub enum SnarkCmd {
    /// Run the mock prover
    Mock,
    /// Generate new proving & verifying keys
    Keygen,
    /// Generate an Axiom compute query
    Run,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// Struct for specifying custom circuit parameters via JSON
pub struct RawCircuitParams {
    pub k: usize,
    pub num_advice_per_phase: Vec<usize>,
    pub num_fixed: usize,
    pub num_lookup_advice_per_phase: Vec<usize>,
    pub lookup_bits: Option<usize>,
    pub num_rlc_columns: Option<usize>,
    pub keccak_rows_per_round: Option<usize>,
    pub max_outputs: Option<usize>,
    pub max_subqueries: Option<usize>,
}

impl std::fmt::Display for SnarkCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock => write!(f, "mock"),
            Self::Keygen => write!(f, "keygen"),
            Self::Run => write!(f, "run"),
        }
    }
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
        long = "data-path",
        help = "For saving build artifacts (optional)"
    )]
    /// The path to save build artifacts
    pub data_path: Option<PathBuf>,
    //Advanced options
    #[arg(
        short = 'c',
        long = "config",
        help = "For specifying custom circuit parameters (optional)"
    )]
    /// The path to a custom circuit configuration
    pub config: Option<PathBuf>,
    /// The path to the KZG params folder
    pub srs: Option<PathBuf>,
}

/// Runs the CLI given on any struct that implements the `AxiomComputeFn` trait
pub fn run_cli_on_scaffold<
    A: AxiomCircuitScaffold<Http, Fr>,
    I: Into<A::InputValue> + DeserializeOwned,
>() {
    let cli = AxiomCircuitRunnerOptions::parse();
    match cli.command {
        SnarkCmd::Mock | SnarkCmd::Run => {
            if cli.input_path.is_none() {
                panic!("The `input_path` argument is required for the selected command.");
            }
        }
        _ => {}
    }
    match cli.command {
        SnarkCmd::Mock | SnarkCmd::Keygen => {
            if cli.degree.is_none() {
                panic!("The `degree` argument is required for the selected command.");
            }
        }
        _ => {
            if cli.degree.is_some() {
                warn!("The `degree` argument is not used for the selected command.");
            }
        }
    }
    let input: Option<A::InputValue> = cli.input_path.map(|input_path| {
        let json_str = fs::read_to_string(input_path).expect("Unable to read file");
        let input: I = serde_json::from_str(&json_str).expect("Unable to parse JSON");
        input.into()
    });
    let provider_uri = cli
        .provider
        .unwrap_or_else(|| env::var("PROVIDER_URI").expect("The `provider` argument is required for the selected command. Either pass it as an argument or set the `PROVIDER_URI` environment variable."));
    let provider = Provider::<Http>::try_from(provider_uri).unwrap();
    let data_path = cli.data_path.unwrap_or_else(|| PathBuf::from("data"));
    let srs_path = cli.srs.unwrap_or_else(|| PathBuf::from("params"));

    let mut max_user_outputs = USER_MAX_OUTPUTS;
    let mut max_subqueries = USER_MAX_SUBQUERIES;

    let params = if let Some(config) = cli.config {
        let f = File::open(config).unwrap();
        let raw_params: RawCircuitParams = serde_json::from_reader(f).unwrap();

        max_user_outputs = raw_params.max_outputs.unwrap_or(USER_MAX_OUTPUTS);
        max_subqueries = raw_params.max_subqueries.unwrap_or(USER_MAX_SUBQUERIES);

        let base_params = BaseCircuitParams {
            k: raw_params.k,
            num_advice_per_phase: raw_params.num_advice_per_phase,
            num_fixed: raw_params.num_fixed,
            num_lookup_advice_per_phase: raw_params.num_lookup_advice_per_phase,
            lookup_bits: raw_params.lookup_bits,
            num_instance_columns: 1,
        };
        if let Some(keccak_rows_per_round) = raw_params.keccak_rows_per_round {
            let rlc_columns = raw_params.num_rlc_columns.unwrap_or(0);
            AxiomCircuitParams::Keccak(RlcKeccakCircuitParams {
                keccak_rows_per_round,
                rlc: RlcCircuitParams {
                    base: base_params,
                    num_rlc_columns: rlc_columns,
                },
            })
        } else if let Some(rlc_columns) = raw_params.num_rlc_columns {
            AxiomCircuitParams::Rlc(RlcCircuitParams {
                base: base_params,
                num_rlc_columns: rlc_columns,
            })
        } else {
            AxiomCircuitParams::Base(base_params)
        }
    } else {
        AxiomCircuitParams::Base(BaseCircuitParams {
            k: cli.degree.unwrap() as usize,
            num_advice_per_phase: vec![4],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: Some(11),
            num_instance_columns: 1,
        })
    };

    let mut runner = AxiomCircuit::<Fr, Http, A>::new(provider.clone(), params)
        .use_max_user_outputs(max_user_outputs)
        .use_max_user_subqueries(max_subqueries);

    match cli.command {
        SnarkCmd::Mock => {
            runner.set_inputs(input);
            mock(&mut runner);
        }
        SnarkCmd::Keygen => {
            let srs = read_srs_from_dir(&srs_path, runner.k() as u32).expect("Unable to read SRS");
            let (_, pk, pinning) = keygen(&mut runner, &srs);
            write_pk(&pk, data_path.join(PathBuf::from("pk.bin")));
            write_pinning(&pinning, data_path.join(PathBuf::from("pinning.json")));
        }
        SnarkCmd::Run => {
            let pinning = read_pinning(data_path.join(PathBuf::from("pinning.json")));
            let mut prover =
                AxiomCircuit::<Fr, Http, A>::prover(provider, pinning.clone()).use_inputs(input);
            let pk = read_pk(data_path.join(PathBuf::from("pk.bin")), &prover);
            let srs = read_srs_from_dir(&srs_path, prover.k() as u32).expect("Unable to read SRS");
            let output = run(&mut prover, &pk, &srs);
            write_output(
                output,
                data_path.join(PathBuf::from("output.snark")),
                data_path.join(PathBuf::from("output.json")),
            );
        }
    }
}

/// Runs the CLI given on any struct that implements the `AxiomComputeFn` trait
pub fn run_cli<A: AxiomComputeFn>()
where
    A::Input<Fr>: Default + Debug,
    A::Input<AssignedValue<Fr>>: Debug,
{
    env_logger::init();
    run_cli_on_scaffold::<AxiomCompute<A>, A::LogicInput>();
}
