use axiom_circuit::{
    axiom_eth::{
        halo2_proofs::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
        halo2curves::bn256::{Bn256, Fr, G1Affine},
    },
    run::inner::run,
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{AxiomCircuitPinning, AxiomV2CircuitOutput},
};
use ethers::providers::{Http, Provider};
use rocket::{serde::json::Json, State};
use serde::de::DeserializeOwned;

#[derive(Clone, Debug)]
pub struct AxiomComputeServer {
    pub pk: ProvingKey<G1Affine>,
    pub pinning: AxiomCircuitPinning,
    pub params: ParamsKZG<Bn256>,
    pub provider: Provider<Http>,
}

pub fn prove<A: AxiomCircuitScaffold<Http, Fr>, I: Into<A::InputValue> + DeserializeOwned>(
    raw_input: Json<I>,
    ctx: &State<AxiomComputeServer>,
) -> Json<AxiomV2CircuitOutput> {
    let pk = &ctx.inner().pk;
    let kzg_params = &ctx.inner().params;
    let provider = ctx.inner().provider.clone();
    let pinning = ctx.inner().pinning.clone();
    let input: A::InputValue = raw_input.into_inner().into();
    let mut runner = AxiomCircuit::<Fr, Http, A>::prover(provider, pinning).use_inputs(Some(input));
    Json(run(&mut runner, pk, kzg_params))
}

#[macro_export]
macro_rules! axiom_scaffold_prover_server {
    ($A:ty, $I:expr) => {
        #[rocket::post("/prove", format = "json", req = "<req>")]
        pub fn prove(
            req: $I,
            ctx: &rocket::State<$AxiomComputeServer>,
        ) -> axiom_circuit::types::AxiomV2CircuitOutput {
            $crate::prove::<$A, _>(req, ctx)
        }
    };
}

#[macro_export]
macro_rules! axiom_compute_prover_server {
    ($A:ty) => {
        #[rocket::post("/prove", format = "json", data = "<req>")]
        pub fn prove(
            req: rocket::serde::json::Json<$A>,
            ctx: &rocket::State<$crate::server::AxiomComputeServer>,
        ) -> rocket::serde::json::Json<axiom_circuit::types::AxiomV2CircuitOutput> {
            axiom_sdk::server::prove::<axiom_sdk::axiom::AxiomCompute<$A>, _>(req, ctx)
        }

        #[rocket::launch]
        fn rocket() -> _ {
            rocket::build().mount("/", rocket::routes![prove])
        }
    };
}
