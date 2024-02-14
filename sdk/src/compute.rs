use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use axiom_circuit::{
    axiom_eth::{
        halo2_base::{gates::RangeChip, AssignedValue},
        halo2_proofs::plonk::{ProvingKey, VerifyingKey},
        halo2curves::bn256::G1Affine,
        rlc::circuit::builder::RlcCircuitBuilder,
        snark_verifier_sdk::Snark,
        utils::hilo::HiLo,
    },
    input::flatten::InputFlatten,
    run::inner::{keygen, mock, prove, run},
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    subquery::caller::SubqueryCaller,
    types::{AxiomCircuitParams, AxiomCircuitPinning, AxiomV2CircuitOutput},
    utils::to_hi_lo,
};
use ethers::providers::{Http, Provider};
use serde::{de::DeserializeOwned, Serialize};

use crate::{api::AxiomAPI, Fr};

/// A trait for the input to an Axiom Compute function
pub trait AxiomComputeInput: Clone + Default + Debug {
    /// The type of the native input (ie. Rust types) to the compute function
    type LogicInput: Clone + Debug + Serialize + DeserializeOwned + Into<Self::Input<Fr>>;
    /// The type of the circuit input to the compute function
    type Input<T: Copy>: Clone + InputFlatten<T>;
}

/// A trait for specifying an Axiom Compute function
pub trait AxiomComputeFn: AxiomComputeInput {
    type FirstPhasePayload: Clone + Default = ();

    /// Axiom Compute function
    fn compute(
        api: &mut AxiomAPI,
        assigned_inputs: Self::Input<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult>;

    /// An optional function that overrides `compute` to specify phase0 circuit logic for circuits that require a challenge
    fn compute_phase0(
        api: &mut AxiomAPI,
        assigned_inputs: Self::Input<AssignedValue<Fr>>,
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
pub struct AxiomCompute<A: AxiomComputeFn> {
    provider: Option<Provider<Http>>,
    params: Option<AxiomCircuitParams>,
    pinning: Option<AxiomCircuitPinning>,
    input: Option<A::LogicInput>,
}

impl<A: AxiomComputeFn> Default for AxiomCompute<A> {
    fn default() -> Self {
        Self {
            provider: None,
            params: None,
            input: None,
            pinning: None,
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
    type FirstPhasePayload = A::FirstPhasePayload;

    fn virtual_assign_phase0(
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
        subquery_caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
        callback: &mut Vec<HiLo<AssignedValue<Fr>>>,
        assigned_inputs: Self::InputWitness,
    ) -> <A as AxiomComputeFn>::FirstPhasePayload {
        let mut api = AxiomAPI::new(builder, range, subquery_caller);
        let (result, payload) = A::compute_phase0(&mut api, assigned_inputs);
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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_provider(&mut self, provider: Provider<Http>) {
        self.provider = Some(provider);
    }

    pub fn set_params(&mut self, params: AxiomCircuitParams) {
        self.params = Some(params);
    }

    pub fn set_inputs(&mut self, input: A::LogicInput) {
        self.input = Some(input);
    }

    pub fn set_pinning(&mut self, pinning: AxiomCircuitPinning) {
        self.pinning = Some(pinning);
    }

    pub fn use_provider(mut self, provider: Provider<Http>) -> Self {
        self.set_provider(provider);
        self
    }

    pub fn use_params(mut self, params: AxiomCircuitParams) -> Self {
        self.set_params(params);
        self
    }

    pub fn use_inputs(mut self, input: A::LogicInput) -> Self {
        self.set_inputs(input);
        self
    }

    pub fn use_pinning(mut self, pinning: AxiomCircuitPinning) -> Self {
        self.set_pinning(pinning);
        self
    }

    fn check_all_set(&self) {
        assert!(self.provider.is_some());
        assert!(self.pinning.is_some());
        assert!(self.input.is_some());
    }

    fn check_provider_and_params_set(&self) {
        assert!(self.provider.is_some());
        assert!(self.params.is_some());
    }

    pub fn mock(&self) {
        self.check_provider_and_params_set();
        let provider = self.provider.clone().unwrap();
        let params = self.params.clone().unwrap();
        let converted_input = self.input.clone().map(|input| input.into());
        mock::<Http, Self>(provider, params, converted_input);
    }

    pub fn keygen(
        &self,
    ) -> (
        VerifyingKey<G1Affine>,
        ProvingKey<G1Affine>,
        AxiomCircuitPinning,
    ) {
        self.check_provider_and_params_set();
        let provider = self.provider.clone().unwrap();
        let params = self.params.clone().unwrap();
        keygen::<Http, Self>(provider, params, None)
    }

    pub fn prove(&self, pk: ProvingKey<G1Affine>) -> Snark {
        self.check_all_set();
        let provider = self.provider.clone().unwrap();
        let converted_input = self.input.clone().map(|input| input.into());
        prove::<Http, Self>(provider, self.pinning.clone().unwrap(), converted_input, pk)
    }

    pub fn run(&self, pk: ProvingKey<G1Affine>) -> AxiomV2CircuitOutput {
        self.check_all_set();
        let provider = self.provider.clone().unwrap();
        let converted_input = self.input.clone().map(|input| input.into());
        run::<Http, Self>(provider, self.pinning.clone().unwrap(), converted_input, pk)
    }

    pub fn circuit(&self) -> AxiomCircuit<Fr, Http, Self> {
        self.check_provider_and_params_set();
        let provider = self.provider.clone().unwrap();
        let params = self.params.clone().unwrap();
        AxiomCircuit::new(provider, params)
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
