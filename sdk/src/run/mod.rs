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
            keccak::decorator::RlcKeccakCircuitParams, snark_verifier::AggregationCircuitParams,
        },
    },
    run::{
        aggregation::{agg_circuit_keygen, agg_circuit_run},
        inner::{keygen, mock, run, witness_gen},
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
    utils::{
        io::{
            read_agg_pk_and_pinning, read_metadata, read_pk_and_pinning, write_agg_keygen_output,
            write_keygen_output, write_metadata, write_output, write_witness_gen_output,
        },
        read_srs_from_dir_or_install,
    },
    Fr,
};

/// Runs the CLI given on any struct that implements the `AxiomComputeFn` trait
pub fn run_cli_on_scaffold<
    A: AxiomCircuitScaffold<Http, Fr>,
    I: Into<A::InputValue> + DeserializeOwned,
>(
    cli: AxiomCircuitRunnerOptions,
) {
    match cli.command {
        SnarkCmd::Mock | SnarkCmd::Prove | SnarkCmd::WitnessGen => {
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
            if cli.degree.is_some() && cli.config.is_some() {
                warn!("The `degree` argument is ignored when a `config` file is provided.");
            }
        }
        _ => {
            if cli.degree.is_some() {
                warn!("The `degree` argument is not used for the selected command.");
            }
            if cli.config.is_some() {
                warn!("The `config` argument is not used for the selected command.");
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
    let srs_path = cli
        .srs
        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".axiom/srs/challenge_0085"));

    let mut max_user_outputs = USER_MAX_OUTPUTS;
    let mut max_subqueries = USER_MAX_SUBQUERIES;
    let mut core_params = A::CoreParams::default();

    let mut agg_circuit_params: Option<AggregationCircuitParams> = None;

    let params = if let Some(config) = cli.config.clone() {
        let f = File::open(config).unwrap();
        let raw_params: RawCircuitParams<A::CoreParams> = serde_json::from_reader(f).unwrap();
        agg_circuit_params = raw_params.agg_params;

        max_user_outputs = raw_params.max_outputs.unwrap_or(USER_MAX_OUTPUTS);
        max_subqueries = raw_params.max_subqueries.unwrap_or(USER_MAX_SUBQUERIES);
        core_params = raw_params
            .core_params
            .unwrap_or_else(A::CoreParams::default);

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
        let degree = if cli.command == SnarkCmd::Prove {
            // The k will be read from the pinning file instead
            12
        } else {
            cli.degree
                .expect("The `degree` argument is required for the selected command.")
                as usize
        };
        AxiomCircuitParams::Base(BaseCircuitParams {
            k: degree,
            num_advice_per_phase: vec![4],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: Some(11),
            num_instance_columns: 1,
        })
    };

    let should_aggregate = cli.should_aggregate;

    let mut runner = AxiomCircuit::<Fr, Http, A>::new(provider.clone(), params)
        .use_core_params(core_params)
        .use_max_user_outputs(max_user_outputs)
        .use_max_user_subqueries(max_subqueries)
        .use_inputs(input.clone());

    match cli.command {
        SnarkCmd::Mock => {
            mock(&mut runner);
        }
        SnarkCmd::Keygen => {
            let srs = read_srs_from_dir_or_install(&srs_path, runner.k() as u32);
            let (vk, pk, pinning) = keygen(&mut runner, &srs);
            write_keygen_output(&vk, &pk, &pinning, cli.data_path.clone());
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

                let prover = AxiomCircuit::<Fr, Http, A>::prover(provider, pinning.clone())
                    .use_inputs(input);
                let output = run(prover, &pk, &srs);
                let agg_kzg_params =
                    read_srs_from_dir_or_install(&srs_path, agg_circuit_params.unwrap().degree);

                let agg_params = agg_circuit_params.unwrap();
                let agg_keygen_output = agg_circuit_keygen(
                    agg_params,
                    output.snark,
                    pinning,
                    &agg_kzg_params,
                    cli.should_auto_config_aggregation_circuit,
                );
                let agg_params = agg_keygen_output.2.params;
                let agg_vk = agg_keygen_output.0.clone();
                write_agg_keygen_output(agg_keygen_output, cli.data_path.clone());
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
                cli.data_path
                    .join(PathBuf::from(format!("{}.json", cli.name))),
            );
        }
        SnarkCmd::Prove => {
            let metadata = read_metadata(
                cli.data_path
                    .join(PathBuf::from(format!("{}.json", cli.name))),
            );
            let circuit_id = metadata.circuit_id.clone();
            let (pk, pinning) = read_pk_and_pinning(cli.data_path.clone(), circuit_id, &runner);
            let prover =
                AxiomCircuit::<Fr, Http, A>::prover(provider, pinning.clone()).use_inputs(input);
            let srs = read_srs_from_dir_or_install(&srs_path, prover.k() as u32);
            let inner_output = run(prover, &pk, &srs);
            let output = if should_aggregate {
                let agg_circuit_id = metadata.agg_circuit_id.expect("No aggregation circuit ID");
                let (agg_pk, agg_pinning) =
                    read_agg_pk_and_pinning::<A::CoreParams>(cli.data_path.clone(), agg_circuit_id);
                let agg_srs = read_srs_from_dir_or_install(&srs_path, agg_pinning.params.degree);
                agg_circuit_run(agg_pinning, inner_output, &agg_pk, &agg_srs)
            } else {
                inner_output
            };
            write_output(
                output,
                cli.data_path.join(PathBuf::from("output.snark")),
                cli.data_path.join(PathBuf::from("output.json")),
            );
        }
        SnarkCmd::WitnessGen => {
            let output = witness_gen(&mut runner);
            write_witness_gen_output(output, cli.data_path.join(PathBuf::from("compute.json")));
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
    let cli = AxiomCircuitRunnerOptions::parse();
    run_cli_on_scaffold::<AxiomCompute<A>, A::LogicInput>(cli);
}
