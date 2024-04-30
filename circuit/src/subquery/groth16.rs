pub use axiom_components::groth16::{MAX_PUBLIC_INPUTS, NUM_FE_PROOF, NUM_FE_VKEY};
use axiom_query::axiom_eth::{halo2_base::AssignedValue, Field};
pub struct Groth16Input<F: Field> {
    pub vkey_bytes: [F; NUM_FE_VKEY],
    pub proof_bytes: [F; NUM_FE_PROOF],
    pub public_inputs: [F; MAX_PUBLIC_INPUTS],
}

pub struct Groth16AssignedInput<F: Field> {
    pub vkey_bytes: [AssignedValue<F>; NUM_FE_VKEY],
    pub proof_bytes: [AssignedValue<F>; NUM_FE_PROOF],
    pub public_inputs: [AssignedValue<F>; MAX_PUBLIC_INPUTS],
}
