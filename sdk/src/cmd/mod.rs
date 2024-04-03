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
            snark_verifier::AggregationCircuitParams,
        },
    },
    run::{
        aggregation::{agg_circuit_keygen, agg_circuit_run},
        inner::{keygen, mock, run},
    },
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::AxiomCircuitParams,
    utils::{get_agg_axiom_client_circuit_metadata, get_axiom_client_circuit_metadata},
};
pub use clap::Parser;
use ethers::providers::{Http, Provider};
use log::warn;
use serde::de::DeserializeOwned;
pub mod types;

use self::types::{AxiomCircuitRunnerOptions, RawCircuitParams, SnarkCmd};
use crate::{
    compute::{AxiomCompute, AxiomComputeFn},
    utils::io::{
        read_agg_pk_and_pinning, read_metadata, read_pk_and_pinning, write_agg_keygen_output,
        write_keygen_output, write_metadata, write_output,
    },
    Fr,
};

impl std::fmt::Display for SnarkCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock => write!(f, "mock"),
            Self::Keygen => write!(f, "keygen"),
            Self::Run => write!(f, "run"),
        }
    }
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
            if cli.degree.is_none() && cli.config.is_none() {
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
    let circuit_name = cli.name.unwrap_or_else(|| "circuit".to_string());

    let mut max_user_outputs = USER_MAX_OUTPUTS;
    let mut max_subqueries = USER_MAX_SUBQUERIES;

    let mut agg_circuit_params: Option<AggregationCircuitParams> = None;

    let params = if let Some(config) = cli.config.clone() {
        let f = File::open(config).unwrap();
        let raw_params: RawCircuitParams = serde_json::from_reader(f).unwrap();
        agg_circuit_params = raw_params.agg_params;

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

    let should_aggregate = cli.should_aggregate;

    let mut runner = AxiomCircuit::<Fr, Http, A>::new(provider.clone(), params)
        .use_max_user_outputs(max_user_outputs)
        .use_max_user_subqueries(max_subqueries)
        .use_inputs(input.clone());

    match cli.command {
        SnarkCmd::Mock => {
            mock(&mut runner);
        }
        SnarkCmd::Keygen => {
            let srs = read_srs_from_dir(&srs_path, runner.k() as u32).expect("Unable to read SRS");
            let (vk, pk, pinning) = keygen(&mut runner, &srs);
            write_keygen_output(&vk, &pk, &pinning, data_path.clone());
            let metadata = if should_aggregate {
                if input.is_none() {
                    panic!("The `input` argument is required for keygen with aggregation.");
                }
                if cli.config.is_none() {
                    panic!("The `config` argument is required for keygen with aggregation.");
                }
                if agg_circuit_params.is_none() {
                    panic!("The `agg_params` field in `config` is required for keygen with aggregation.");
                }

                let mut prover = AxiomCircuit::<Fr, Http, A>::prover(provider, pinning.clone())
                    .use_inputs(input);
                let output = run(&mut prover, &pk, &srs);
                let agg_kzg_params =
                    read_srs_from_dir(&srs_path, agg_circuit_params.unwrap().degree)
                        .expect("Unable to read SRS");
                let agg_params = agg_circuit_params.unwrap();
                let agg_keygen_output = agg_circuit_keygen(
                    agg_params,
                    output.snark,
                    pinning,
                    &agg_kzg_params,
                    cli.should_auto_config_aggregation_circuit,
                );
                let agg_params = agg_keygen_output.2.params.clone();
                let agg_vk = agg_keygen_output.0.clone();
                write_agg_keygen_output(agg_keygen_output, data_path.clone());
                get_agg_axiom_client_circuit_metadata(
                    &runner,
                    &agg_kzg_params,
                    &vk,
                    &agg_vk,
                    agg_params.into(),
                )
            } else {
                get_axiom_client_circuit_metadata(&runner, &srs, &vk)
            };
            write_metadata(
                metadata,
                data_path.join(PathBuf::from(format!("{}.json", circuit_name))),
            );
        }
        SnarkCmd::Run => {
            let metadata =
                read_metadata(data_path.join(PathBuf::from(format!("{}.json", circuit_name))));
            let circuit_id = metadata.circuit_id.clone();
            let (pk, pinning) = read_pk_and_pinning(data_path.clone(), circuit_id, &runner);
            let mut prover =
                AxiomCircuit::<Fr, Http, A>::prover(provider, pinning.clone()).use_inputs(input);
            let srs = read_srs_from_dir(&srs_path, prover.k() as u32).expect("Unable to read SRS");
            let inner_output = run(&mut prover, &pk, &srs);
            let output = if should_aggregate {
                let agg_circuit_id = metadata.agg_circuit_id.expect("No aggregation circuit ID");
                let (agg_pk, agg_pinning) =
                    read_agg_pk_and_pinning(data_path.clone(), agg_circuit_id);
                let agg_srs = read_srs_from_dir(&srs_path, agg_pinning.params.degree)
                    .expect("Unable to read SRS");
                agg_circuit_run(agg_pinning, inner_output, &agg_pk, &agg_srs)
            } else {
                inner_output
            };
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
