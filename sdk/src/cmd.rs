use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
};

use axiom_circuit::{
    axiom_eth::{
        halo2_base::{gates::circuit::BaseCircuitParams, AssignedValue},
        halo2_proofs::{plonk::ProvingKey, SerdeFormat},
        halo2curves::bn256::G1Affine,
        rlc::circuit::RlcCircuitParams,
        utils::keccak::decorator::RlcKeccakCircuitParams,
    },
    scaffold::AxiomCircuit,
    types::{AxiomCircuitParams, AxiomCircuitPinning},
};
pub use clap::Parser;
use clap::Subcommand;
use ethers::providers::{Http, Provider};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::{
    compute::{AxiomCompute, AxiomComputeFn},
    Fr,
};

#[derive(Clone, Copy, Debug, Subcommand)]
/// Circuit CLI commands
pub enum SnarkCmd {
    /// Run the mock prover
    Mock,
    /// Generate new proving & verifying keys
    Keygen,
    /// Generate a new proof
    Prove,
    /// Generate an Axiom compute query
    Run,
    /// Perform witness generation only, for axiom-std
    WitnessGen,
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
}

impl std::fmt::Display for SnarkCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock => write!(f, "mock"),
            Self::Keygen => write!(f, "keygen"),
            Self::Prove => write!(f, "prove"),
            Self::Run => write!(f, "run"),
            Self::WitnessGen => write!(f, "witness-gen"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Command-line helper for building Axiom compute circuits
pub struct Cli {
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
}

/// Runs the CLI given on any struct that implements the `AxiomComputeFn` trait
pub fn run_cli<A: AxiomComputeFn>()
where
    A::Input<Fr>: Default + Debug,
    A::Input<AssignedValue<Fr>>: Debug,
{
    let cli = Cli::parse();
    match cli.command {
        SnarkCmd::Mock | SnarkCmd::Prove | SnarkCmd::Run | SnarkCmd::WitnessGen => {
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
    let input_path = cli.input_path.unwrap();
    let json_str = fs::read_to_string(input_path).expect("Unable to read file");
    let input: A::LogicInput = serde_json::from_str(&json_str).expect("Unable to parse JSON");
    let provider_uri = cli
        .provider
        .unwrap_or_else(|| env::var("PROVIDER_URI").expect("The `provider` argument is required for the selected command. Either pass it as an argument or set the `PROVIDER_URI` environment variable."));
    let provider = Provider::<Http>::try_from(provider_uri).unwrap();
    let data_path = cli.data_path.unwrap_or_else(|| PathBuf::from("data"));

    let params = if let Some(config) = cli.config {
        let f = File::open(config).unwrap();
        let raw_params: RawCircuitParams = serde_json::from_reader(f).unwrap();
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

    match cli.command {
        SnarkCmd::Mock => {
            AxiomCompute::<A>::new()
                .use_inputs(input)
                .use_params(params)
                .use_provider(provider)
                .mock();
        }
        SnarkCmd::Keygen => {
            let circuit = AxiomCompute::<A>::new()
                .use_params(params)
                .use_provider(provider);
            let (_, pkey, pinning) = circuit.keygen();
            let pk_path = data_path.join(PathBuf::from("pk.bin"));
            if pk_path.exists() {
                fs::remove_file(&pk_path).unwrap();
            }
            let f = File::create(&pk_path)
                .unwrap_or_else(|_| panic!("Could not create file at {pk_path:?}"));
            let mut writer = BufWriter::new(f);
            pkey.write(&mut writer, SerdeFormat::RawBytes)
                .expect("writing pkey should not fail");
            // let vk_path = data_path.join(PathBuf::from("vk.bin"));
            // if vk_path.exists() {
            //     fs::remove_file(&vk_path).unwrap();
            // }
            // let f = File::create(&vk_path)
            //     .unwrap_or_else(|_| panic!("Could not create file at {vk_path:?}"));
            // let mut writer = BufWriter::new(f);
            // vkey.write(&mut writer, SerdeFormat::RawBytes)
            //     .expect("writing vkey should not fail");

            let pinning_path = data_path.join(PathBuf::from("pinning.json"));
            if pinning_path.exists() {
                fs::remove_file(&pinning_path).unwrap();
            }
            let f = File::create(&pinning_path)
                .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
            serde_json::to_writer_pretty(&f, &pinning)
                .expect("writing circuit pinning should not fail");
        }
        SnarkCmd::Prove => {
            let pinning_path = data_path.join(PathBuf::from("pinning.json"));
            let f = File::open(pinning_path).unwrap();
            let pinning: AxiomCircuitPinning = serde_json::from_reader(f).unwrap();
            let compute = AxiomCompute::<A>::new()
                .use_pinning(pinning.clone())
                .use_provider(provider);
            let pk_path = data_path.join(PathBuf::from("pk.bin"));
            let mut f = File::open(pk_path).unwrap();
            let pk = ProvingKey::<G1Affine>::read::<_, AxiomCircuit<Fr, Http, AxiomCompute<A>>>(
                &mut f,
                SerdeFormat::RawBytes,
                pinning.params,
            )
            .unwrap();
            compute.use_inputs(input).prove(pk);
        }
        SnarkCmd::Run => {
            let pinning_path = data_path.join(PathBuf::from("pinning.json"));
            let f = File::open(pinning_path).unwrap();
            let pinning: AxiomCircuitPinning = serde_json::from_reader(f).unwrap();
            let compute = AxiomCompute::<A>::new()
                .use_pinning(pinning.clone())
                .use_provider(provider);
            let pk_path = data_path.join(PathBuf::from("pk.bin"));
            let mut f = File::open(pk_path).unwrap();
            let pk = ProvingKey::<G1Affine>::read::<_, AxiomCircuit<Fr, Http, AxiomCompute<A>>>(
                &mut f,
                SerdeFormat::RawBytes,
                pinning.params,
            )
            .unwrap();
            let output = compute.use_inputs(input).run(pk);
            let output_path = data_path.join(PathBuf::from("output.snark"));
            let f = File::create(&output_path)
                .unwrap_or_else(|_| panic!("Could not create file at {output_path:?}"));
            bincode::serialize_into(f, &output.snark).expect("Writing SNARK should not fail");
            let output_json_path = data_path.join(PathBuf::from("output.json"));
            if output_json_path.exists() {
                fs::remove_file(&output_json_path).unwrap();
            }
            let f = File::create(&output_json_path)
                .unwrap_or_else(|_| panic!("Could not create file at {output_json_path:?}"));
            serde_json::to_writer_pretty(&f, &output.data).expect("Writing output should not fail");
        }
        SnarkCmd::WitnessGen => {
            let circuit = AxiomCompute::<A>::new()
                .use_params(params.clone())
                .use_provider(provider.clone());
            let (_, _, pinning) = circuit.keygen();
            let results = circuit.use_pinning(pinning).use_inputs(input).witness_gen();

            let output_path = data_path.join(PathBuf::from("compute.json"));
            let f = File::create(&output_path)
                .unwrap_or_else(|_| panic!("Could not create file at {output_path:?}"));
            serde_json::to_writer_pretty(f, &results.compute_results)
                .expect("Writing compute results should not fail");
        }
    }
}
