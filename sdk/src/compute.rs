use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use axiom_circuit::{
    axiom_codec::constants::{USER_MAX_OUTPUTS, USER_MAX_SUBQUERIES},
    axiom_eth::{
        halo2_base::{gates::RangeChip, AssignedValue},
        halo2_proofs::{
            plonk::{ProvingKey, VerifyingKey},
            poly::kzg::commitment::ParamsKZG,
        },
        halo2curves::bn256::{Bn256, G1Affine},
        rlc::circuit::builder::RlcCircuitBuilder,
        utils::hilo::HiLo,
    },
    input::flatten::InputFlatten,
    run::inner::{keygen, mock, run},
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    subquery::caller::SubqueryCaller,
    types::{AxiomCircuitParams, AxiomCircuitPinning, AxiomV2CircuitOutput},
    utils::to_hi_lo,
};
use ethers::providers::{Http, Provider};
use serde::{de::DeserializeOwned, Serialize};

use crate::{api::AxiomAPI, Fr};

/// A trait for specifying the input to an Axiom Compute function
pub trait AxiomComputeInput: Clone + Default + Debug {
    /// The type of the native input (ie. Rust types) to the compute function
    type LogicInput: Clone + Debug + Serialize + DeserializeOwned + Into<Self::Input<Fr>>;
    /// The type of the circuit input to the compute function
    type Input<T: Copy>: Clone + InputFlatten<T, Params = Self::CoreParams>;
    /// Optional type to specify circuit-specific configuration params
    type CoreParams: Clone + Debug + Default + Serialize + DeserializeOwned = ();
}

/// A trait for specifying an Axiom Compute function
pub trait AxiomComputeFn: AxiomComputeInput {
    /// An optional type for the first phase payload -- only needed if you are using `compute_phase1`
    type FirstPhasePayload: Clone + Default = ();

    /// Axiom Compute function
    fn compute(
        api: &mut AxiomAPI,
        assigned_inputs: Self::Input<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult>;

    #[allow(unused_variables)]
    /// An optional function that overrides `compute` to specify phase0 circuit logic for circuits that require a challenge
    fn compute_phase0(
        api: &mut AxiomAPI,
        assigned_inputs: Self::Input<AssignedValue<Fr>>,
        core_params: Self::CoreParams,
    ) -> (Vec<AxiomResult>, Self::FirstPhasePayload) {
        (Self::compute(api, assigned_inputs), Default::default())
    }

    #[allow(unused_variables)]
    /// An optional function to specify phase1 circuit logic for circuits that require a challenge
    ///
    /// This function is called after the phase0 circuit logic has been executed
    fn compute_phase1(
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
        payload: Self::FirstPhasePayload,
    ) {
    }
}

#[derive(Debug, Clone)]
/// Helper struct that contains all the necessary metadata and inputs to run an Axiom Compute function
pub struct AxiomCompute<A: AxiomComputeFn> {
    provider: Option<Provider<Http>>,
    params: Option<AxiomCircuitParams>,
    pinning: Option<AxiomCircuitPinning<A::CoreParams>>,
    input: Option<A::LogicInput>,
    kzg_params: Option<ParamsKZG<Bn256>>,
    max_user_outputs: usize,
    max_user_subqueries: usize,
}

impl<A: AxiomComputeFn> Default for AxiomCompute<A> {
    fn default() -> Self {
        Self {
            provider: None,
            params: None,
            input: None,
            pinning: None,
            max_user_outputs: USER_MAX_OUTPUTS,
            max_user_subqueries: USER_MAX_SUBQUERIES,
            kzg_params: None,
        }
    }
}

impl<A: AxiomComputeFn> AxiomCircuitScaffold<Http, Fr> for AxiomCompute<A>
where
    A::Input<Fr>: Default + Debug,
    A::Input<AssignedValue<Fr>>: Debug,
{
    type InputValue = A::Input<Fr>;
    type InputWitness = A::Input<AssignedValue<Fr>>;
    type CoreParams = A::CoreParams;
    type FirstPhasePayload = A::FirstPhasePayload;

    fn virtual_assign_phase0(
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
        subquery_caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
        callback: &mut Vec<HiLo<AssignedValue<Fr>>>,
        assigned_inputs: Self::InputWitness,
        core_params: Self::CoreParams,
    ) -> <A as AxiomComputeFn>::FirstPhasePayload {
        let mut api = AxiomAPI::new(builder, range, subquery_caller);
        let (result, payload) = A::compute_phase0(&mut api, assigned_inputs, core_params);
        let hilo_output = result
            .into_iter()
            .map(|result| match result {
                AxiomResult::HiLo(hilo) => hilo,
                AxiomResult::AssignedValue(val) => to_hi_lo(api.ctx(), range, val),
            })
            .collect::<Vec<_>>();
        callback.extend(hilo_output);
        payload
    }

    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
        payload: Self::FirstPhasePayload,
    ) {
        A::compute_phase1(builder, range, payload);
    }
}

impl<A: AxiomComputeFn> AxiomCompute<A>
where
    A::Input<Fr>: Default + Debug,
    A::Input<AssignedValue<Fr>>: Debug,
{
    /// Create a new AxiomCompute instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the provider for the AxiomCompute instance
    pub fn set_provider(&mut self, provider: Provider<Http>) {
        self.provider = Some(provider);
    }

    /// Set the params for the AxiomCompute instance
    pub fn set_params(&mut self, params: AxiomCircuitParams) {
        self.params = Some(params);
    }

    /// Set the inputs for the AxiomCompute instance
    pub fn set_inputs(&mut self, input: A::LogicInput) {
        self.input = Some(input);
    }

    /// Set the pinning for the AxiomCompute instance
    pub fn set_pinning(&mut self, pinning: AxiomCircuitPinning<A::CoreParams>) {
        self.pinning = Some(pinning);
    }

    // Set the maximum number of user outputs
    pub fn set_max_user_outputs(&mut self, max_user_outputs: usize) {
        self.max_user_outputs = max_user_outputs;
    }

    // Set the maximum number of user subqueries
    pub fn set_max_user_subqueries(&mut self, max_user_subqueries: usize) {
        self.max_user_subqueries = max_user_subqueries;
    }

    /// Set the KZG parameters for the AxiomCompute instance
    pub fn set_kzg_params(&mut self, kzg_params: ParamsKZG<Bn256>) {
        self.kzg_params = Some(kzg_params);
    }

    /// Use the given provider for the AxiomCompute instance
    pub fn use_provider(mut self, provider: Provider<Http>) -> Self {
        self.set_provider(provider);
        self
    }

    /// Use the given params for the AxiomCompute instance
    pub fn use_params(mut self, params: AxiomCircuitParams) -> Self {
        self.set_params(params);
        self
    }

    /// Use the given inputs for the AxiomCompute instance
    pub fn use_inputs(mut self, input: A::LogicInput) -> Self {
        self.set_inputs(input);
        self
    }

    /// Use the given pinning for the AxiomCompute instance
    pub fn use_pinning(mut self, pinning: AxiomCircuitPinning<A::CoreParams>) -> Self {
        self.set_pinning(pinning);
        self
    }

    /// Use the given maximum number of user outputs
    pub fn use_max_user_outputs(mut self, max_user_outputs: usize) -> Self {
        self.set_max_user_outputs(max_user_outputs);
        self
    }

    /// Use the given maximum number of user subqueries
    pub fn use_max_user_subqueries(mut self, max_user_subqueries: usize) -> Self {
        self.set_max_user_subqueries(max_user_subqueries);
        self
    }

    /// Use the given KZG parameters for the AxiomCompute instance
    pub fn use_kzg_params(mut self, kzg_params: ParamsKZG<Bn256>) -> Self {
        self.set_kzg_params(kzg_params);
        self
    }

    /// Check that all the necessary configurations are set
    fn check_all_set(&self) {
        assert!(self.provider.is_some());
        assert!(self.pinning.is_some());
        assert!(self.input.is_some());
    }

    /// Check that the provider and params are set
    fn check_provider_and_params_set(&self) {
        assert!(self.provider.is_some());
        assert!(self.params.is_some());
    }

    /// Run the mock prover
    pub fn mock(&self) {
        self.check_provider_and_params_set();
        let provider = self.provider.clone().unwrap();
        let params = self.params.clone().unwrap();
        let converted_input = self.input.clone().map(|input| input.into());
        let mut runner = AxiomCircuit::<_, _, Self>::new(provider, params)
            .use_inputs(converted_input)
            .use_max_user_outputs(self.max_user_outputs)
            .use_max_user_subqueries(self.max_user_subqueries);
        mock::<Http, Self>(&mut runner);
    }

    /// Run key generation and return the proving and verifying keys, and the circuit pinning
    pub fn keygen(
        &self,
    ) -> (
        VerifyingKey<G1Affine>,
        ProvingKey<G1Affine>,
        AxiomCircuitPinning<A::CoreParams>,
    ) {
        self.check_provider_and_params_set();
        let provider = self.provider.clone().unwrap();
        let params = self.params.clone().unwrap();
        let mut runner = AxiomCircuit::<_, _, Self>::new(provider, params)
            .use_max_user_outputs(self.max_user_outputs)
            .use_max_user_subqueries(self.max_user_subqueries);
        let kzg_params = self.kzg_params.clone().expect("KZG params not set");
        keygen::<Http, Self>(&mut runner, &kzg_params)
    }

    /// Run the prover and return the outputs needed to make an on-chain compute query
    pub fn run(&self, pk: ProvingKey<G1Affine>) -> AxiomV2CircuitOutput {
        self.check_all_set();
        let provider = self.provider.clone().unwrap();
        let converted_input = self.input.clone().map(|input| input.into());
        let runner = AxiomCircuit::<_, _, Self>::prover(provider, self.pinning.clone().unwrap())
            .use_inputs(converted_input)
            .use_max_user_outputs(self.max_user_outputs)
            .use_max_user_subqueries(self.max_user_subqueries);
        let kzg_params = self.kzg_params.clone().expect("KZG params not set");
        run::<Http, Self>(runner, &pk, &kzg_params)
    }

    /// Returns an [AxiomCircuit] instance, for functions that expect the halo2 circuit trait
    pub fn circuit(&self) -> AxiomCircuit<Fr, Http, Self> {
        self.check_provider_and_params_set();
        let provider = self.provider.clone().unwrap();
        let params = self.params.clone().unwrap();
        let converted_input = self.input.clone().map(|input| input.into());
        AxiomCircuit::new(provider, params)
            .use_max_user_outputs(self.max_user_outputs)
            .use_max_user_subqueries(self.max_user_subqueries)
            .use_inputs(converted_input)
    }
}

/// A `bytes32` value that your callback contract receives upon query fulfillment
pub enum AxiomResult {
    HiLo(HiLo<AssignedValue<Fr>>),
    AssignedValue(AssignedValue<Fr>),
}

impl From<HiLo<AssignedValue<Fr>>> for AxiomResult {
    fn from(result: HiLo<AssignedValue<Fr>>) -> Self {
        Self::HiLo(result)
    }
}

impl From<AssignedValue<Fr>> for AxiomResult {
    fn from(result: AssignedValue<Fr>) -> Self {
        Self::AssignedValue(result)
    }
}
