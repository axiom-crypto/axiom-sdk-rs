//! ## axiom-sdk
//!
//! ### Installation
//!
//! To install our Rust circuit SDK into a Cargo project, run:
//! ```bash
//! cargo add axiom-sdk
//! ```
//!
//! ### Overview
//!
//! To implement an Axiom circuit using the Rust SDK you need to:
//!
//! - Specify an input struct that consists of native Rust types and `ethers-rs` types (ie. `u64`, `Address`, `H256`, etc.). The struct name must end with `Input` (ie. `MyCircuitInput`).
//! - Implement the `AxiomComputeFn` trait on your input struct
//!
//! ### Input Specification
//!
//! Your input struct can contain native Rust types (ie. `u64`, `[usize; N]`, etc.) and `ethers-rs` types (ie. `Address`, `H256`, etc.), and its name must end with `Input` (ie. `MyCircuitInput`).
//! Additional types can be used if they implement the `RawInput` trait (see [here](./circuit/src/input/raw_input.rs)).
//! The struct must be annotated with the #[AxiomComputeInput] attribute so that it implements the sufficient circuit traits.
//! This attribute will also generate a new struct with `Input` replaced with `CircuitInput` (ie. `AccountAgeInput` -> `AccountAgeCircuitInput`), which has all the fields of the specified struct,
//! but with `halo2-lib` types to be used inside your circuit (like `AssignedValue<Fr>`).
//!
//! Here is an example:
//!
//! ```ignore
//! #[AxiomComputeInput]
//! pub struct AccountAgeInput {
//!     pub addr: Address,
//!     pub claimed_block_number: u64,
//! }
//! ```
//!
//! ### Compute Function Specification
//!
//! You must implement the `AxiomComputeFn` on your input struct. There is only one trait function that you must implement:
//! ```ignore
//! fn compute(
//!     api: &mut AxiomAPI,
//!     assigned_inputs: AccountAgeCircuitInput<AssignedValue<Fr>>,
//! ) -> Vec<AxiomResult>
//! ```
//! where `AccountAgeCircuitInput` should be replaced with your derived circuit input struct.
//!
//! The `AxiomAPI` struct gives you access to subquery calling functions in addition to a `RlcCircuitBuilder` to specify your circuit.
//! Your compute function should then return any values that you wish to pass on-chain in the `Vec<AxiomResult>` -- an `AxiomResult` is either an enum of either `HiLo<AssignedValue<Fr>>` or `AssignedValue<Fr>` (in which case it is converted to hi-lo for you).
//!
//! Here is an example:
//! ```ignore
//! impl AxiomComputeFn for AccountAgeInput {
//!     fn compute(
//!         api: &mut AxiomAPI,
//!         assigned_inputs: AccountAgeCircuitInput<AssignedValue<Fr>>,
//!     ) -> Vec<AxiomResult> {
//!         let gate = GateChip::new();
//!         let zero = api.ctx().load_zero();
//!         let one = api.ctx().load_constant(Fr::one());
//!         let prev_block = gate.sub(api.ctx(), assigned_inputs.claimed_block_number, one);
//!
//!         let account_prev_block = api.get_account(prev_block, assigned_inputs.addr);
//!         let prev_nonce = account_prev_block.call(AccountField::Nonce);
//!         let prev_nonce = api.from_hi_lo(prev_nonce);
//!         api.ctx().constrain_equal(&prev_nonce, &zero);
//!
//!         let account = api.get_account(assigned_inputs.claimed_block_number, assigned_inputs.addr);
//!         let curr_nonce = account.call(AccountField::Nonce);
//!         let curr_nonce = api.from_hi_lo(curr_nonce);
//!
//!         api.range.check_less_than(api.ctx(), zero, curr_nonce, 40);
//!
//!         vec![
//!             assigned_inputs.addr.into(),
//!             assigned_inputs.claimed_block_number.into(),
//!         ]
//!     }
//! }
//! ```
//!
//! ### Running The Circuit
//!
//! To run your circuit, create a `main` function call the `run_cli` function with your input struct as the generic parameter:
//! ```ignore
//! fn main() {
//!     env_logger::init();
//!     run_cli::<AccountAgeInput>();
//! }
//! ```
//! The `main` function will run a CLI that allows you to run mock proving, key generation, and proving of your circuit. The CLI has the following commands:
//!
//! ```ignore
//! Commands:
//!     mock    Run the mock prover
//!     keygen  Generate new proving & verifying keys
//!     prove   Generate a new proof
//!     run     Generate an Axiom compute query
//!     help    Print this message or the help of the given subcommand(s)
//!
//! Options:
//!     -k, --degree <DEGREE>        To determine the size of your circuit (12..25)
//!     -p, --provider <PROVIDER>    JSON RPC provider URI
//!     -i, --input <INPUT_PATH>     JSON inputs to feed into your circuit
//!     -d, --data-path <DATA_PATH>  For saving build artifacts (optional)
//!     -c, --config <CONFIG>        For custom advanced usage only (optional)
//!     -h, --help                   Print help
//!     -V, --version                Print version
//! ```
//!
//! For example:
//!
//! ```bash
//! cargo run --example account_age -- --input data/account_age_input.json -k 12 -p <PROVIDER_URI> <CMD>
//! ```
//!
//! where `PROVIDER_URI` is a JSON-RPC URI, and `CMD` is `mock`, `prove`, `keygen`, or `run`.

#![allow(incomplete_features)]
#![feature(associated_type_defaults)]
mod api;

// pub(crate) mod utils;
pub use axiom_circuit::{
    self,
    axiom_codec::HiLo,
    axiom_eth::{halo2_base, halo2curves::bn256::Fr},
};

/// The types and traits required to implement an Axiom Compute function
pub mod axiom {
    pub use axiom_sdk_derive::AxiomComputeInput;

    pub use crate::{
        api::AxiomAPI,
        compute::{AxiomCompute, AxiomComputeFn, AxiomComputeInput, AxiomResult},
    };
}
/// Contains a CLI for running any Axiom Compute function (any struct that implements the `AxiomComputeFn` trait)
pub mod cli;
/// Contains the traits and types required to implement an Axiom Compute function (re-exported from the `axiom` module)
pub(crate) mod compute;
/// Contains a web server for running any Axiom Compute function (any struct that implements the `AxiomComputeFn` trait)
pub mod server;
/// Module with all subquery types and builders
pub mod subquery;
/// Re-export ethers-rs
pub use ethers;
/// Run either the proving/keygen CLI or the server from the same binary
pub mod bin;
/// Module with utility functions for running the CLI
pub mod utils;
