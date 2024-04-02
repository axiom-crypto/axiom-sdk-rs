use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axiom_circuit::{
    axiom_eth::{
        halo2_proofs::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        utils::build_utils::keygen::read_srs_from_dir,
    },
    run::{aggregation::agg_circuit_run, inner::run},
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{
        AggregationCircuitPinning, AxiomCircuitPinning, AxiomV2CircuitOutput, AxiomV2DataAndResults,
    },
};
use clap::Parser;
use ethers::providers::{Http, Provider};
use rocket::State;
use serde::{de::DeserializeOwned, Serialize};

use crate::utils::io::{read_agg_pk_and_pinning, read_metadata, read_pinning, read_pk};

#[derive(Clone, Debug)]
pub struct AxiomComputeCircuitCtx {
    pub pk: ProvingKey<G1Affine>,
    pub pinning: AxiomCircuitPinning,
    pub params: ParamsKZG<Bn256>,
}

#[derive(Clone, Debug)]
pub struct AggregationCircuitCtx {
    pub pk: ProvingKey<G1Affine>,
    pub pinning: AggregationCircuitPinning,
    pub params: ParamsKZG<Bn256>,
}

#[derive(Clone, Debug)]
pub struct AxiomComputeCtx {
    pub child: AxiomComputeCircuitCtx,
    pub agg: Option<AggregationCircuitCtx>,
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
    pub data_path: String,
    pub circuit_name: String,
    pub provider: String,
    pub srs_path: String,
}

pub async fn add_job(ctx: &State<AxiomComputeManager>, job: String) -> u64 {
    let mut hasher = DefaultHasher::new();
    job.hash(&mut hasher);
    let job_id = hasher.finish();
    if ctx.inputs.lock().unwrap().contains_key(&job_id) {
        return job_id;
    }
    ctx.job_queue.lock().unwrap().push(job_id);
    ctx.inputs.lock().unwrap().insert(job_id, job);
    ctx.job_status
        .lock()
        .unwrap()
        .insert(job_id, AxiomComputeJobStatus::Received);
    job_id
}

pub fn prover_loop<A: AxiomCircuitScaffold<Http, Fr>, I: Into<A::InputValue> + DeserializeOwned>(
    manager: AxiomComputeManager,
    ctx: AxiomComputeCtx,
    mut shutdown: tokio::sync::mpsc::Receiver<()>,
) {
    loop {
        let job = {
            let mut queue = manager.job_queue.lock().unwrap();
            queue.pop()
        };

        if let Some(job) = job {
            let inputs = {
                let inputs_lock = manager.inputs.lock().unwrap();
                inputs_lock.clone()
            };
            let raw_input = inputs.get(&job).unwrap();
            let input: I = serde_json::from_str(raw_input).unwrap();
            let mut runner = AxiomCircuit::<Fr, Http, A>::prover(
                ctx.provider.clone(),
                ctx.child.pinning.clone(),
            )
            .use_inputs(Some(input.into()));
            let scaffold_output = runner.scaffold_output();
            manager
                .job_status
                .lock()
                .unwrap()
                .insert(job, AxiomComputeJobStatus::DataQueryReady);
            manager
                .data_query
                .lock()
                .unwrap()
                .insert(job, scaffold_output);
            let inner_output = run(&mut runner, &ctx.child.pk, &ctx.child.params);
            manager
                .job_status
                .lock()
                .unwrap()
                .insert(job, AxiomComputeJobStatus::InnerOutputReady);
            let output = if ctx.agg.is_some() {
                let agg_ctx = ctx.agg.as_ref().unwrap();
                agg_circuit_run(
                    agg_ctx.pinning.clone(),
                    inner_output,
                    &agg_ctx.pk,
                    &agg_ctx.params,
                )
            } else {
                inner_output
            };
            manager.outputs.lock().unwrap().insert(job, output);
            manager
                .job_status
                .lock()
                .unwrap()
                .insert(job, AxiomComputeJobStatus::OutputReady);
        } else {
            if shutdown.try_recv().is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

pub fn initialize<A: AxiomCircuitScaffold<Http, Fr>>(
    options: AxiomComputeServerCmd,
) -> AxiomComputeCtx {
    let data_path = PathBuf::from(options.data_path);
    let srs_path = PathBuf::from(options.srs_path);
    let metadata =
        read_metadata(data_path.join(PathBuf::from(format!("{}.json", options.circuit_name))));
    let provider = Provider::<Http>::try_from(options.provider).unwrap();
    let circuit_id = metadata.circuit_id.clone();
    let pinning = read_pinning(data_path.join(format!("{}.pinning", circuit_id)));
    let runner = AxiomCircuit::<Fr, Http, A>::new(provider.clone(), pinning.clone().params)
        .use_pinning(pinning.clone());
    let pk = read_pk(data_path.join(format!("{}.pk", circuit_id)), &runner);
    let params = read_srs_from_dir(&srs_path, runner.k() as u32).expect("Unable to read SRS");

    let agg = metadata.agg_circuit_id.map(|agg_circuit_id| {
        let (agg_pk, agg_pinning) = read_agg_pk_and_pinning(data_path.clone(), agg_circuit_id);
        let agg_params =
            read_srs_from_dir(&srs_path, agg_pinning.params.degree).expect("Unable to read SRS");
        AggregationCircuitCtx {
            pk: agg_pk,
            pinning: agg_pinning,
            params: agg_params,
        }
    });

    AxiomComputeCtx {
        child: AxiomComputeCircuitCtx {
            pk,
            pinning,
            params,
        },
        agg,
        provider,
    }
}
#[rocket::get("/job_status/<id>")]
pub async fn get_job_status(
    id: u64,
    ctx: &rocket::State<crate::server::AxiomComputeManager>,
) -> (rocket::http::Status, String) {
    let job_status = ctx.job_status.lock().unwrap();
    match job_status.get(&id) {
        Some(status) => (rocket::http::Status::Ok, format!("{:?}", status)),
        None => (rocket::http::Status::NotFound, "Job not found".to_string()),
    }
}

#[rocket::get("/data_query/<id>")]
pub async fn get_data_query(
    id: u64,
    ctx: &rocket::State<crate::server::AxiomComputeManager>,
) -> (rocket::http::Status, String) {
    let data_query = ctx.data_query.lock().unwrap();
    match data_query.get(&id) {
        Some(query) => (
            rocket::http::Status::Ok,
            serde_json::to_string(query).unwrap(),
        ),
        None => (
            rocket::http::Status::NotFound,
            "Data query not found".to_string(),
        ),
    }
}

#[rocket::get("/circuit_output/<id>")]
pub async fn get_circuit_output(
    id: u64,
    ctx: &rocket::State<crate::server::AxiomComputeManager>,
) -> (rocket::http::Status, String) {
    let outputs = ctx.outputs.lock().unwrap();
    match outputs.get(&id) {
        Some(output) => (
            rocket::http::Status::Ok,
            serde_json::to_string(output).unwrap(),
        ),
        None => (
            rocket::http::Status::NotFound,
            "Circuit output not found".to_string(),
        ),
    }
}

#[macro_export]
macro_rules! axiom_compute_prover_server {
    ($A:ty) => {
        #[rocket::post("/start_proving_job", format = "json", data = "<req>")]
        pub async fn start_proving_job(
            req: rocket::serde::json::Json<$A>,
            ctx: &rocket::State<$crate::server::AxiomComputeManager>,
        ) -> String {
            let input = serde_json::to_string(&req.into_inner()).unwrap();
            let id = $crate::server::add_job(ctx, input).await;
            id.to_string()
        }

        #[rocket::main]
        async fn main() -> Result<(), rocket::Error> {
            let options = <$crate::server::AxiomComputeServerCmd as clap::Parser>::parse();
            let job_queue: $crate::server::AxiomComputeManager = Default::default();
            let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
            let worker_manager = job_queue.clone();
            std::thread::spawn(|| {
                let ctx = $crate::server::initialize::<$crate::axiom::AxiomCompute<$A>>(options);
                $crate::server::prover_loop::<$crate::axiom::AxiomCompute<$A>, $A>(
                    worker_manager,
                    ctx,
                    shutdown_rx,
                );
            });
            rocket::build()
                .manage(job_queue)
                .mount(
                    "/",
                    rocket::routes![
                        start_proving_job,
                        $crate::server::get_job_status,
                        $crate::server::get_data_query,
                        $crate::server::get_circuit_output
                    ],
                )
                .launch()
                .await?;

            Ok(())
        }
    };
}
