use std::sync::{Arc, Mutex};

use axiom_circuit::{
    axiom_codec::HiLo,
    axiom_eth::{
        halo2_base::{gates::RangeChip, safe_types::SafeTypeChip, AssignedValue, Context},
        keccak::promise::{KeccakFixLenCall, KeccakVarLenCall},
        rlc::circuit::builder::RlcCircuitBuilder,
        utils::uint_to_bytes_be,
    },
    subquery::{
        caller::SubqueryCaller,
        groth16::{Groth16AssignedInput, MAX_PUBLIC_INPUTS, NUM_FE_PROOF, NUM_FE_VKEY},
        types::ECDSAComponentInput,
    },
    utils::{from_hi_lo, to_hi_lo},
};
use ethers::providers::Http;

use crate::{
    subquery::{
        account::{get_account, Account},
        header::{get_header, Header},
        mapping::{get_mapping, SolidityMapping},
        receipt::{get_receipt, Receipt},
        storage::{get_storage, Storage},
        tx::{get_tx, Tx},
    },
    Fr,
};

/// Axiom Circuit API for making both subquery calls (e.g. `get_account`, `get_header`, etc.) and for more general ZK primitives (e.g. `add`, `mul`, etc.).
pub struct AxiomAPI<'a> {
    /// The `halo2-lib` struct used to construct the circuit
    pub builder: &'a mut RlcCircuitBuilder<Fr>,
    /// The main chip for ZK primitives
    pub range: &'a RangeChip<Fr>,
    /// The struct that manages all subquery calls
    subquery_caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
}

impl<'a> AxiomAPI<'a> {
    pub fn new(
        builder: &'a mut RlcCircuitBuilder<Fr>,
        range: &'a RangeChip<Fr>,
        subquery_caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
    ) -> Self {
        Self {
            builder,
            range,
            subquery_caller,
        }
    }

    /// Returns a thread-safe [SubqueryCaller] object.
    pub fn subquery_caller(&self) -> Arc<Mutex<SubqueryCaller<Http, Fr>>> {
        self.subquery_caller.clone()
    }

    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    /// * `phase`: The challenge phase (as an index) of the gate thread.
    pub fn ctx(&mut self) -> &mut Context<Fr> {
        self.builder.base.main(0)
    }

    /// Returns an `AssignedValue<Fr>` from a `HiLo<AssignedValue<Fr>>`.
    ///
    /// NOTE: this can fail if the hi-lo pair is greater than the `Fr` modulus. See `check_hi_lo` for what is constrained.
    ///
    /// * `hilo` - The `HiLo<AssignedValue<Fr>>` object to convert.
    pub fn from_hi_lo(&mut self, hilo: HiLo<AssignedValue<Fr>>) -> AssignedValue<Fr> {
        let ctx = self.builder.base.main(0);
        from_hi_lo(ctx, self.range, hilo)
    }

    /// Returns a 256-bit `HiLo<AssignedValue<Fr>>` from a `AssignedValue<Fr>`.
    ///
    /// See `check_hi_lo` for what is constrained.
    ///
    /// * `val` - The `AssignedValue<Fr>` object to convert.
    pub fn to_hi_lo(&mut self, val: AssignedValue<Fr>) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        to_hi_lo(ctx, self.range, val)
    }

    /// Decomposes a `AssignedValue<Fr>` into bytes, in big-endian, and returns the bytes.
    ///
    /// * `uint` - The `AssignedValue<Fr>` object to convert.
    /// * `num_bytes` - The number of bytes in `uint`.
    pub fn to_bytes_be(
        &mut self,
        uint: AssignedValue<Fr>,
        num_bytes: usize,
    ) -> Vec<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        uint_to_bytes_be(ctx, self.range, &uint, num_bytes)
            .iter()
            .map(|x| *x.as_ref())
            .collect()
    }

    /// Returns an [Account] builder given block number and address.
    ///
    /// * `block_number` - The block number as an `AssignedValue<Fr>`.
    /// * `addr` - The address as an `AssignedValue<Fr>`.
    pub fn get_account(
        &mut self,
        block_number: AssignedValue<Fr>,
        addr: AssignedValue<Fr>,
    ) -> Account {
        let ctx = self.builder.base.main(0);
        get_account(ctx, self.subquery_caller.clone(), block_number, addr)
    }

    /// Returns a [Header] builder given block number.
    ///
    /// * `block_number` - The block number as an `AssignedValue<Fr>`.
    pub fn get_header(&mut self, block_number: AssignedValue<Fr>) -> Header {
        let ctx = self.builder.base.main(0);
        get_header(ctx, self.subquery_caller.clone(), block_number)
    }

    /// Returns a [SolidityMapping] builder given block number, address, and mapping slot.
    ///
    /// * `block_number` - The block number as an `AssignedValue<Fr>`.
    /// * `addr` - The address as an `AssignedValue<Fr>`.
    /// * `mapping_slot` - The mapping slot as a `HiLo<AssignedValue<Fr>`.
    pub fn get_mapping(
        &mut self,
        block_number: AssignedValue<Fr>,
        addr: AssignedValue<Fr>,
        mapping_slot: HiLo<AssignedValue<Fr>>,
    ) -> SolidityMapping {
        let ctx = self.builder.base.main(0);
        get_mapping(
            ctx,
            self.subquery_caller.clone(),
            block_number,
            addr,
            mapping_slot,
        )
    }

    /// Returns a [Receipt] builder given block number and transaction index.
    ///
    /// * `block_number` - The block number as an `AssignedValue<Fr>`.
    /// * `tx_idx` - The transaction index as an `AssignedValue<Fr>`.
    pub fn get_receipt(
        &mut self,
        block_number: AssignedValue<Fr>,
        tx_idx: AssignedValue<Fr>,
    ) -> Receipt {
        let ctx = self.builder.base.main(0);
        get_receipt(ctx, self.subquery_caller.clone(), block_number, tx_idx)
    }

    /// Returns a [Storage] builder given block number and address.
    ///
    /// * `block_number` - The block number as an `AssignedValue<Fr>`.
    /// * `addr` - The address as an `AssignedValue<Fr>`.
    pub fn get_storage(
        &mut self,
        block_number: AssignedValue<Fr>,
        addr: AssignedValue<Fr>,
    ) -> Storage {
        let ctx = self.builder.base.main(0);
        get_storage(ctx, self.subquery_caller.clone(), block_number, addr)
    }

    /// Returns a [Tx] builder given block number and transaction index.
    ///
    /// * `block_number` - The block number as an `AssignedValue<Fr>`.
    /// * `tx_idx` - The transaction index as an `AssignedValue<Fr>`.
    pub fn get_tx(&mut self, block_number: AssignedValue<Fr>, tx_idx: AssignedValue<Fr>) -> Tx {
        let ctx = self.builder.base.main(0);
        get_tx(ctx, self.subquery_caller.clone(), block_number, tx_idx)
    }

    pub fn ecdsa_sig_verify(
        &mut self,
        pubkey: (HiLo<AssignedValue<Fr>>, HiLo<AssignedValue<Fr>>),
        r: HiLo<AssignedValue<Fr>>,
        s: HiLo<AssignedValue<Fr>>,
        msg_hash: HiLo<AssignedValue<Fr>>,
    ) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        let subquery_caller = self.subquery_caller.clone();
        let mut subquery_caller = subquery_caller.lock().unwrap();

        let input = ECDSAComponentInput {
            pubkey,
            r,
            s,
            msg_hash,
        };

        subquery_caller.call(ctx, input)
    }

    pub fn groth16_verify(
        &mut self,
        vkey_bytes: &[AssignedValue<Fr>; NUM_FE_VKEY],
        proof_bytes: &[AssignedValue<Fr>; NUM_FE_PROOF],
        public_inputs: &[AssignedValue<Fr>; MAX_PUBLIC_INPUTS],
    ) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        let subquery_caller = self.subquery_caller.clone();
        let mut subquery_caller = subquery_caller.lock().unwrap();

        let input = Groth16AssignedInput {
            vkey_bytes: *vkey_bytes,
            proof_bytes: *proof_bytes,
            public_inputs: *public_inputs,
        };

        subquery_caller.groth16_verify(ctx, self.range, input)
    }

    pub fn keccak_fix_len(&mut self, bytes: Vec<AssignedValue<Fr>>) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        let subquery_caller = self.subquery_caller.clone();
        let mut subquery_caller = subquery_caller.lock().unwrap();

        let safe_type_chip = SafeTypeChip::new(self.range);
        let len = bytes.len();
        let bytes = safe_type_chip.raw_to_fix_len_bytes_vec(ctx, bytes, len);

        subquery_caller.keccak(ctx, KeccakFixLenCall::new(bytes))
    }

    pub fn keccak_var_len(
        &mut self,
        bytes: Vec<AssignedValue<Fr>>,
        len: AssignedValue<Fr>,
        max_len: usize,
    ) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        let subquery_caller = self.subquery_caller.clone();
        let mut subquery_caller = subquery_caller.lock().unwrap();

        let safe_type_chip = SafeTypeChip::new(self.range);
        let bytes = safe_type_chip.raw_to_var_len_bytes_vec(ctx, bytes, len, max_len);

        subquery_caller.keccak(ctx, KeccakVarLenCall::new(bytes, 0))
    }

    pub fn keccak_fix_len_unsafe(
        &mut self,
        bytes: Vec<AssignedValue<Fr>>,
    ) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        let subquery_caller = self.subquery_caller.clone();
        let mut subquery_caller = subquery_caller.lock().unwrap();

        let len = bytes.len();
        let bytes = SafeTypeChip::unsafe_to_fix_len_bytes_vec(bytes, len);

        subquery_caller.keccak(ctx, KeccakFixLenCall::new(bytes))
    }

    pub fn keccak_var_len_unsafe(
        &mut self,
        bytes: Vec<AssignedValue<Fr>>,
        len: AssignedValue<Fr>,
        max_len: usize,
    ) -> HiLo<AssignedValue<Fr>> {
        let ctx = self.builder.base.main(0);
        let subquery_caller = self.subquery_caller.clone();
        let mut subquery_caller = subquery_caller.lock().unwrap();

        let bytes = SafeTypeChip::unsafe_to_var_len_bytes_vec(bytes, len, max_len);

        subquery_caller.keccak(ctx, KeccakVarLenCall::new(bytes, 0))
    }
}
