use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use axiom_codec::{
    constants::MAX_SUBQUERY_INPUTS,
    types::{field_elements::SUBQUERY_RESULT_LEN, native::AnySubquery},
    HiLo,
};
use axiom_components::{
    framework::utils::compute_poseidon,
    groth16::{
        get_groth16_consts_from_max_pi, native::verify_groth16,
        types::Groth16VerifierComponentInput, unflatten_groth16_input, NUM_FE_PER_CHUNK,
    },
};
use axiom_query::axiom_eth::{
    halo2_base::{gates::RangeChip, AssignedValue, Context, ContextTag},
    keccak::promise::{KeccakFixLenCall, KeccakVarLenCall},
    utils::{encode_h256_to_hilo, uint_to_bytes_be},
    Field,
};
use ethers::{
    providers::{JsonRpcClient, Provider},
    types::H256,
};
use itertools::Itertools;

use super::{
    groth16::Groth16AssignedInput,
    keccak::{KeccakSubquery, KeccakSubqueryTypes},
    types::Subquery,
};
use crate::subquery::{types::RawSubquery, utils::get_subquery_type_from_any_subquery};

pub trait FetchSubquery<F: Field>: Clone {
    fn flatten(&self) -> Vec<AssignedValue<F>>;
    fn fetch<P: JsonRpcClient>(&self, p: &Provider<P>) -> Result<H256>;
    fn any_subquery(&self) -> AnySubquery;
    fn call<P: JsonRpcClient>(
        &self,
        ctx: &mut Context<F>,
        caller: &mut SubqueryCaller<P, F>,
    ) -> HiLo<AssignedValue<F>> {
        caller.call(ctx, self.clone())
    }
}

pub struct SubqueryCaller<P: JsonRpcClient, F: Field> {
    pub provider: Provider<P>,
    pub subqueries: BTreeMap<ContextTag, Vec<(AnySubquery, H256)>>,
    pub subquery_assigned_values: BTreeMap<ContextTag, Vec<AssignedValue<F>>>,
    pub keccak_fix_len_calls: Vec<(KeccakFixLenCall<F>, HiLo<AssignedValue<F>>)>,
    pub keccak_var_len_calls: Vec<(KeccakVarLenCall<F>, HiLo<AssignedValue<F>>)>,
    subquery_cache: HashMap<AnySubquery, H256>,
    groth16_max_pi: usize,
    // if true, the fetched subquery will always be H256::zero()
    mock_subquery_call: bool,
}

impl<P: JsonRpcClient, F: Field> SubqueryCaller<P, F> {
    pub fn new(provider: Provider<P>, groth16_max_pi: usize, mock: bool) -> Self {
        Self {
            provider,
            subqueries: BTreeMap::new(),
            subquery_assigned_values: BTreeMap::new(),
            keccak_fix_len_calls: Vec::new(),
            keccak_var_len_calls: Vec::new(),
            mock_subquery_call: mock,
            subquery_cache: HashMap::new(),
            groth16_max_pi,
        }
    }

    pub fn clear(&mut self) {
        self.subqueries.clear();
        self.subquery_assigned_values.clear();
        self.keccak_fix_len_calls.clear();
        self.keccak_var_len_calls.clear();
    }

    pub fn data_query(&self) -> Vec<Subquery> {
        let subqueries: Vec<Subquery> = self
            .subqueries
            .values()
            .flat_map(|val| {
                val.iter()
                    .map(|(any_subquery, result)| Subquery {
                        subquery_type: get_subquery_type_from_any_subquery(&any_subquery.clone()),
                        subquery_data: RawSubquery(any_subquery.clone()),
                        val: *result,
                    })
                    .collect_vec()
            })
            .collect_vec();
        subqueries
    }

    pub fn instances(&self) -> Vec<AssignedValue<F>> {
        self.subquery_assigned_values
            .values()
            .flatten()
            .cloned()
            .collect_vec()
    }

    // `handle_subquery` adds the subquery to the list of subqueries, to the circuit's public instances, and returns the HiLo result.
    fn handle_subquery<T: FetchSubquery<F>>(
        &mut self,
        ctx: &mut Context<F>,
        subquery: T,
        result: H256,
    ) -> HiLo<AssignedValue<F>> {
        let any_subquery = subquery.any_subquery();
        let val = (any_subquery.clone(), result);
        self.subqueries
            .entry(ctx.tag())
            .and_modify(|thread| thread.push(val.clone()))
            .or_insert(vec![val]);
        let subquery_type = get_subquery_type_from_any_subquery(&any_subquery);
        let hilo = encode_h256_to_hilo(&result);
        let hi = ctx.load_witness(hilo.hi());
        let lo = ctx.load_witness(hilo.lo());
        let subquery_type_assigned_value = ctx.load_constant(F::from(subquery_type));
        let hi_lo_vec = vec![hi, lo];
        let mut input = subquery.flatten();
        input.resize_with(MAX_SUBQUERY_INPUTS, || ctx.load_constant(F::ZERO));
        let mut flattened_subquery = vec![subquery_type_assigned_value];
        flattened_subquery.extend(input);
        flattened_subquery.extend(hi_lo_vec);
        assert_eq!(flattened_subquery.len(), SUBQUERY_RESULT_LEN);
        self.subquery_assigned_values
            .entry(ctx.tag())
            .and_modify(|thread| thread.extend(flattened_subquery.clone()))
            .or_insert(flattened_subquery);
        HiLo::from_hi_lo([hi, lo])
    }

    // The `call` function fetches the subquery result and then calls `handle_subquery` to process the subquery + result.
    pub fn call<T: FetchSubquery<F>>(
        &mut self,
        ctx: &mut Context<F>,
        subquery: T,
    ) -> HiLo<AssignedValue<F>> {
        let result = if self.mock_subquery_call {
            H256::zero()
        } else if let std::collections::hash_map::Entry::Vacant(e) =
            self.subquery_cache.entry(subquery.any_subquery())
        {
            let val = subquery.fetch(&self.provider).unwrap();
            e.insert(val);
            val
        } else {
            *self.subquery_cache.get(&subquery.any_subquery()).unwrap()
        };
        self.handle_subquery(ctx, subquery, result)
    }

    pub fn keccak<T: KeccakSubquery<F>>(
        &mut self,
        ctx: &mut Context<F>,
        subquery: T,
    ) -> HiLo<AssignedValue<F>> {
        let logic_input = subquery.to_logical_input();
        let output_fe = logic_input.compute_output();
        let hi = ctx.load_witness(output_fe.hash.hi());
        let lo = ctx.load_witness(output_fe.hash.lo());
        let hilo = HiLo::from_hi_lo([hi, lo]);
        match subquery.subquery_type() {
            KeccakSubqueryTypes::FixLen(call) => {
                self.keccak_fix_len_calls.push((call, hilo));
            }
            KeccakSubqueryTypes::VarLen(call) => {
                self.keccak_var_len_calls.push((call, hilo));
            }
        };
        hilo
    }

    pub fn groth16_verify(
        &mut self,
        ctx: &mut Context<F>,
        range: &RangeChip<F>,
        input: Groth16AssignedInput<F>,
    ) -> HiLo<AssignedValue<F>> {
        let constants = get_groth16_consts_from_max_pi(self.groth16_max_pi);
        let mut fe = input.vkey_bytes;
        fe.extend(input.proof_bytes);
        fe.extend(input.public_inputs);
        assert_eq!(fe.len(), constants.num_fe_per_input);
        let zero = ctx.load_witness(F::ZERO);
        fe.resize_with(constants.max_num_fe_per_input_no_hash, || zero);
        let to_hash = fe
            .iter()
            .map(|v| *v.value())
            .collect::<Vec<_>>()
            .chunks(NUM_FE_PER_CHUNK)
            .collect::<Vec<_>>()
            .iter()
            .flat_map(|x| {
                let mut x = x.to_vec();
                let first_fe_bytes = x[0].to_bytes_le();
                x[0] = F::from_bytes_le(&first_fe_bytes[..31]);
                x
            })
            .collect::<Vec<_>>();
        let hash = compute_poseidon(&to_hash);
        let res = ctx.load_witness(hash);
        fe.push(res);
        let unflattened = unflatten_groth16_input(
            fe.iter().map(|v| *v.value()).collect_vec(),
            self.groth16_max_pi,
        );
        let res = verify_groth16(unflattened, constants.max_pi);
        assert_eq!(fe.len(), constants.max_num_fe_per_input);
        let subqueries = fe
            .chunks(NUM_FE_PER_CHUNK)
            .map(|x| {
                let x = x.to_vec();
                let res = uint_to_bytes_be(ctx, range, &x[0], 32)[0];
                (
                    Groth16VerifierComponentInput {
                        packed_bytes: x.into(),
                    },
                    *res,
                )
            })
            .collect_vec();
        assert_eq!(subqueries.len(), constants.num_chunks);
        let mut outputs = vec![H256::from_low_u64_be(2); constants.num_chunks - 1];
        outputs.push(H256::from_low_u64_be(res as u64));
        let subquery_output_pairs = subqueries
            .into_iter()
            .zip(outputs)
            .map(|((subquery, res), output)| {
                let hilo_output = self.handle_subquery(ctx, subquery, output);
                ctx.constrain_equal(&hilo_output.lo(), &res);
                hilo_output
            })
            .collect_vec();
        *subquery_output_pairs.last().unwrap()
    }
}
