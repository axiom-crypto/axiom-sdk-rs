use std::{
    collections::hash_map::DefaultHasher,
    env,
    fmt::Debug,
    hash::{Hash, Hasher},
    path::PathBuf,
};

use axiom_circuit::{
    axiom_eth::{
        halo2_base::AssignedValue, halo2curves::bn256::Fr,
        utils::build_utils::keygen::read_srs_from_dir,
    },
    run::{aggregation::agg_circuit_run, inner::run},
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::AxiomV2CircuitOutput,
};
use ethers::providers::{Http, Provider};
use rocket::State;
use serde::de::DeserializeOwned;
use tokio::runtime::Runtime;

use self::types::{
    AggregationCircuitCtx, AxiomComputeCircuitCtx, AxiomComputeCtx, AxiomComputeJobStatus,
    AxiomComputeManager, AxiomComputeServerCmd,
};
use crate::{
    compute::{AxiomCompute, AxiomComputeFn},
    utils::io::{read_agg_pk_and_pinning, read_metadata, read_pinning, read_pk},
};

pub mod types;

pub trait AxiomClientProvingServer: AxiomCircuitScaffold<Http, Fr> {
    type Context: Clone = ();
    type ServerPayload = ();
    type RequestInput: DeserializeOwned;

    fn construct_context(params: Self::CoreParams) -> Self::Context;
    async fn process_input(
        ctx: Self::Context,
        input: Self::RequestInput,
        provider: Provider<Http>,
    ) -> Result<(Self::InputValue, Self::ServerPayload), String>;
    #[allow(unused_variables)]
    fn callback(
        ctx: Self::Context,
        payload: Self::ServerPayload,
        output: AxiomV2CircuitOutput,
    ) -> Result<(), ()> {
        Ok(())
    }
}

impl<A: AxiomComputeFn> AxiomClientProvingServer for AxiomCompute<A>
where
    A::Input<Fr>: Default + Debug,
    A::Input<AssignedValue<Fr>>: Debug,
{
    type Context = ();
    type RequestInput = A::LogicInput;
    fn construct_context(_: A::CoreParams) -> Self::Context {
        ()
    }
    async fn process_input(
        _ctx: Self::Context,
        input: Self::RequestInput,
        _provider: Provider<Http>,
    ) -> Result<(A::Input<Fr>, ()), String> {
        Ok((input.into(), ()))
    }
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

pub fn prover_loop<A: AxiomClientProvingServer>(
    manager: AxiomComputeManager,
    ctx: AxiomComputeCtx<A>,
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
            let input: A::RequestInput = serde_json::from_str(raw_input).unwrap();
            let rt = Runtime::new().unwrap();
            let processed_input = rt.block_on(async {
                A::process_input(ctx.server_ctx.clone(), input, ctx.provider.clone()).await
            });
            if processed_input.is_err() {
                manager
                    .job_status
                    .lock()
                    .unwrap()
                    .insert(job, AxiomComputeJobStatus::ErrorInputPrep);
                continue;
            }
            let (processed_input, payload) = processed_input.unwrap();
            let runner = AxiomCircuit::<Fr, Http, A>::prover(
                ctx.provider.clone(),
                ctx.child.pinning.clone(),
            )
            .use_inputs(Some(processed_input));
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
            let inner_output = run(runner, &ctx.child.pk, &ctx.child.params);
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
            manager.outputs.lock().unwrap().insert(job, output.clone());
            manager
                .job_status
                .lock()
                .unwrap()
                .insert(job, AxiomComputeJobStatus::OutputReady);
            let callback = A::callback(ctx.server_ctx.clone(), payload, output);
            let callback_status = if callback.is_ok() {
                AxiomComputeJobStatus::CallbackSuccess
            } else {
                AxiomComputeJobStatus::ErrorCallback
            };
            manager
                .job_status
                .lock()
                .unwrap()
                .insert(job, callback_status);
        } else {
            if shutdown.try_recv().is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

pub fn initialize<A: AxiomClientProvingServer>(
    options: AxiomComputeServerCmd,
) -> AxiomComputeCtx<A> {
    let data_path = PathBuf::from(options.data_path);
    let srs_path = PathBuf::from(options.srs_path);
    let metadata =
        read_metadata(data_path.join(PathBuf::from(format!("{}.json", options.circuit_name))));
    let provider_uri = options
        .provider
        .unwrap_or_else(|| env::var("PROVIDER_URI").expect("The `provider` argument is required. Either pass it as an argument or set the `PROVIDER_URI` environment variable."));
    let provider = Provider::<Http>::try_from(provider_uri).unwrap();
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

    let server_ctx = A::construct_context(pinning.clone().core_params);

    AxiomComputeCtx {
        child: AxiomComputeCircuitCtx {
            pk,
            pinning,
            params,
        },
        agg,
        provider,
        server_ctx,
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
            req: rocket::serde::json::Json<
                <$A as $crate::server::AxiomClientProvingServer>::RequestInput,
            >,
            ctx: &rocket::State<$crate::server::types::AxiomComputeManager>,
        ) -> String {
            let input = serde_json::to_string(&req.into_inner()).unwrap();
            let id = $crate::server::add_job(ctx, input).await;
            id.to_string()
        }

        async fn server(
            options: $crate::server::types::AxiomComputeServerCmd,
        ) -> Result<(), rocket::Error> {
            let job_queue: $crate::server::types::AxiomComputeManager = Default::default();
            let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
            let worker_manager = job_queue.clone();
            std::thread::spawn(|| {
                let ctx = $crate::server::initialize::<$A>(options);
                $crate::server::prover_loop::<$A>(worker_manager, ctx, shutdown_rx);
            });
            rocket::build()
                .configure(rocket::Config {
                    address: std::str::FromStr::from_str("0.0.0.0").unwrap(),
                    port: 8000,
                    ..rocket::Config::default()
                })
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