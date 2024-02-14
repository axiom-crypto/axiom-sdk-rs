use std::sync::{Arc, Mutex};

use axiom_circuit::{
    axiom_codec::HiLo,
    axiom_eth::halo2_base::{AssignedValue, Context},
    subquery::{caller::SubqueryCaller, types::AssignedStorageSubquery},
};
use ethers::providers::Http;

use crate::Fr;

/// Storage subquery builder
pub struct Storage<'a> {
    pub block_number: AssignedValue<Fr>,
    pub addr: AssignedValue<Fr>,
    ctx: &'a mut Context<Fr>,
    caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
}

pub(crate) fn get_storage(
    ctx: &mut Context<Fr>,
    caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
    block_number: AssignedValue<Fr>,
    addr: AssignedValue<Fr>,
) -> Storage {
    Storage {
        block_number,
        addr,
        ctx,
        caller,
    }
}

impl<'a> Storage<'a> {
    /// Fetches the storage subquery and returns the HiLo<AssignedValue<Fr>> result
    ///
    /// * `slot` - The storage slot to fetch
    pub fn slot(self, slot: HiLo<AssignedValue<Fr>>) -> HiLo<AssignedValue<Fr>> {
        let mut subquery_caller = self.caller.lock().unwrap();
        let subquery = AssignedStorageSubquery {
            block_number: self.block_number,
            addr: self.addr,
            slot,
        };
        subquery_caller.call(self.ctx, subquery)
    }
}
