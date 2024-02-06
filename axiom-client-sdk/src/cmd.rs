use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
};

use axiom_client::{
    axiom_eth::{
        halo2_base::{gates::circuit::BaseCircuitParams, AssignedValue},
        halo2_proofs::{plonk::ProvingKey, SerdeFormat},
        halo2curves::bn256::G1Affine,
        rlc::virtual_region::RlcThreadBreakPoints,
    },
    scaffold::AxiomCircuit,
    types::AxiomCircuitParams,
};
pub use clap::Parser;
use clap::Subcommand;
use ethers::providers::{Http, Provider};

use crate::{
    compute::{AxiomCompute, AxiomComputeFn},
    Fr,
};

#[derive(Clone, Copy, Debug, Subcommand)]
pub enum SnarkCmd {
    /// Run the mock prover
    Mock,
    /// Generate new proving & verifying keys
    Keygen,
    /// Generate a new proof
    Prove,
    /// Generate an Axiom compute query
    Run,
}

impl std::fmt::Display for SnarkCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock => write!(f, "mock"),
            Self::Keygen => write!(f, "keygen"),
            Self::Prove => write!(f, "prove"),
            Self::Run => write!(f, "run"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Command-line helper for building Axiom compute circuits
pub struct Cli {
    #[command(subcommand)]
    pub command: SnarkCmd,
    #[arg(short = 'k', long = "degree")]
    pub degree: u32,
    #[arg(short = 'p', long = "provider")]
    pub provider: Option<String>,
    #[arg(short, long = "input")]
    pub input_path: Option<PathBuf>,
    #[arg(short, long = "data-path")]
    pub data_path: Option<PathBuf>,
}

pub fn run_cli<A: AxiomComputeFn>()
where
    A::Input<Fr>: Default + Debug,
    A::Input<AssignedValue<Fr>>: Debug,
{
    let cli = Cli::parse();
    match cli.command {
        SnarkCmd::Mock | SnarkCmd::Prove | SnarkCmd::Run => {
            if cli.input_path.is_none() {
                panic!("The `input_path` argument is required for the selected command.");
            }
        }
        _ => {}
    }
    let input_path = cli.input_path.unwrap();
    let json_str = fs::read_to_string(input_path).expect("Unable to read file");
    let input: A::LogicInput = serde_json::from_str(&json_str).expect("Unable to parse JSON");
    if cli.provider.is_none() && env::var("PROVIDER_URI").is_err() {
        panic!("The `provider` argument is required for the selected command. Either pass it as an argument or set the `PROVIDER_URI` environment variable.");
    }
    let provider_uri = cli
        .provider
        .unwrap_or_else(|| env::var("PROVIDER_URI").unwrap());
    let provider = Provider::<Http>::try_from(provider_uri).unwrap();
    let data_path = cli.data_path.unwrap_or_else(|| PathBuf::from("data"));

    let params = BaseCircuitParams {
        k: 12,
        num_advice_per_phase: vec![4],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![1],
        lookup_bits: Some(11),
        num_instance_columns: 1,
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
            let (vkey, pkey, breakpoints) = circuit.keygen();
            let pk_path = data_path.join(PathBuf::from("pk.bin"));
            if pk_path.exists() {
                fs::remove_file(&pk_path).unwrap();
            }
            let vk_path = data_path.join(PathBuf::from("vk.bin"));
            if vk_path.exists() {
                fs::remove_file(&vk_path).unwrap();
            }
            let f = File::create(&vk_path)
                .unwrap_or_else(|_| panic!("Could not create file at {vk_path:?}"));
            let mut writer = BufWriter::new(f);
            vkey.write(&mut writer, SerdeFormat::RawBytes)
                .expect("writing vkey should not fail");

            let f = File::create(&pk_path)
                .unwrap_or_else(|_| panic!("Could not create file at {pk_path:?}"));
            let mut writer = BufWriter::new(f);
            pkey.write(&mut writer, SerdeFormat::RawBytes)
                .expect("writing pkey should not fail");

            let breakpoints_path = data_path.join(PathBuf::from("breakpoints.json"));
            if breakpoints_path.exists() {
                fs::remove_file(&breakpoints_path).unwrap();
            }
            let f = File::create(&breakpoints_path)
                .unwrap_or_else(|_| panic!("Could not create file at {breakpoints_path:?}"));
            let mut writer = BufWriter::new(f);
            serde_json::to_writer_pretty(&mut writer, &breakpoints)
                .expect("writing breakpoints should not fail");
        }
        SnarkCmd::Prove => {
            let compute = AxiomCompute::<A>::new()
                .use_params(params.clone())
                .use_provider(provider);
            let pk_path = data_path.join(PathBuf::from("pk.bin"));
            let mut f = File::open(&pk_path).unwrap();
            let pk = ProvingKey::<G1Affine>::read::<_, AxiomCircuit<Fr, Http, AxiomCompute<A>>>(
                &mut f,
                SerdeFormat::RawBytes,
                AxiomCircuitParams::Base(params),
            )
            .unwrap();
            let breakpoints_path = data_path.join(PathBuf::from("breakpoints.json"));
            let f = File::open(&breakpoints_path).unwrap();
            let breakpoints: RlcThreadBreakPoints = serde_json::from_reader(f).unwrap();
            compute.use_inputs(input).prove(pk, breakpoints);
        }
        SnarkCmd::Run => {
            let compute = AxiomCompute::<A>::new()
                .use_params(params.clone())
                .use_provider(provider);
            let pk_path = data_path.join(PathBuf::from("pk.bin"));
            let mut f = File::open(&pk_path).unwrap();
            let pk = ProvingKey::<G1Affine>::read::<_, AxiomCircuit<Fr, Http, AxiomCompute<A>>>(
                &mut f,
                SerdeFormat::RawBytes,
                AxiomCircuitParams::Base(params),
            )
            .unwrap();
            let breakpoints_path = data_path.join(PathBuf::from("breakpoints.json"));
            let f = File::open(&breakpoints_path).unwrap();
            let breakpoints: RlcThreadBreakPoints = serde_json::from_reader(f).unwrap();
            compute.use_inputs(input).run(pk, breakpoints);
        }
    }
}
