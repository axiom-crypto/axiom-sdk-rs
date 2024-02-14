use std::sync::{Arc, Mutex};

use axiom_circuit::{
    axiom_codec::HiLo,
    axiom_eth::halo2_base::{AssignedValue, Context},
    subquery::{caller::SubqueryCaller, types::AssignedAccountSubquery, AccountField},
};
use ethers::providers::Http;

use crate::Fr;

/// Account subquery builder
pub struct Account<'a> {
    pub block_number: AssignedValue<Fr>,
    pub addr: AssignedValue<Fr>,
    ctx: &'a mut Context<Fr>,
    caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
}

pub(crate) fn get_account(
    ctx: &mut Context<Fr>,
    caller: Arc<Mutex<SubqueryCaller<Http, Fr>>>,
    block_number: AssignedValue<Fr>,
    addr: AssignedValue<Fr>,
) -> Account {
    Account {
        block_number,
        addr,
        ctx,
        caller,
    }
}

impl<'a> Account<'a> {
    /// Fetches the account subquery and returns the HiLo<AssignedValue<Fr>> result
    ///
    /// * `field` - The account field to fetch
    pub fn call(self, field: AccountField) -> HiLo<AssignedValue<Fr>> {
        let field_constant = self.ctx.load_constant(Fr::from(field));
        let mut subquery_caller = self.caller.lock().unwrap();
        let subquery = AssignedAccountSubquery {
            block_number: self.block_number,
            addr: self.addr,
            field_idx: field_constant,
        };
        subquery_caller.call(self.ctx, subquery)
    }
}
