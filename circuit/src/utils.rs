use std::env;

use anyhow::anyhow;
use axiom_codec::{
    encoder::native::get_query_schema_hash,
    types::native::{AxiomV2ComputeQuery, AxiomV2ComputeSnark, SubqueryResult},
    utils::native::decode_hilo_to_h256,
    HiLo,
};
use axiom_query::{
    axiom_eth::{
        halo2_base::{
            gates::{GateInstructions, RangeChip, RangeInstructions},
            utils::{biguint_to_fe, modulus},
            AssignedValue, Context,
            QuantumCell::Constant,
        },
        halo2_proofs::plonk::VerifyingKey,
        halo2curves::{
            bn256::{Bn256, G1Affine},
            group::GroupEncoding,
        },
        snark_verifier::{
            pcs::{
                kzg::{KzgAccumulator, KzgDecidingKey, LimbsEncoding},
                AccumulatorEncoding,
            },
            verifier::{plonk::PlonkProof, SnarkVerifier},
        },
        snark_verifier_sdk::{
            halo2::{PoseidonTranscript, POSEIDON_SPEC},
            NativeLoader, PlonkVerifier, Snark, BITS, LIMBS, SHPLONK,
        },
        utils::{keccak::decorator::RlcKeccakCircuitParams, snark_verifier::NUM_FE_ACCUMULATOR},
        Field,
    },
    components::results::types::LogicOutputResultsRoot,
    verify_compute::utils::{
        get_metadata_from_protocol, get_onchain_vk_from_protocol, get_onchain_vk_from_vk,
        reconstruct_snark_from_compute_query, write_onchain_vkey,
    },
};
use dotenv::dotenv;
use ethers::{
    providers::{Http, Provider},
    types::{Bytes, H256},
};
use itertools::Itertools;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

use crate::types::{AxiomCircuitParams, AxiomV2CircuitOutput, AxiomV2DataAndResults};

const NUM_BYTES_ACCUMULATOR: usize = 64;

pub fn build_axiom_v2_compute_query(
    snark: Snark,
    params: AxiomCircuitParams,
    results: AxiomV2DataAndResults,
    max_user_outputs: usize,
) -> AxiomV2ComputeQuery {
    let rlc_keccak_params = RlcKeccakCircuitParams::from(params);
    let rlc_params = rlc_keccak_params.clone().rlc;
    let metadata =
        get_metadata_from_protocol(&snark.protocol, rlc_params, max_user_outputs).unwrap();
    let k = rlc_keccak_params.k();
    let partial_vk = get_onchain_vk_from_protocol(&snark.protocol, metadata.clone());
    let partial_vk_output = write_onchain_vkey(&partial_vk).unwrap();
    let result_len = results.compute_results.len() as u16;
    let kzg_accumulator = if metadata.is_aggregation {
        let agg_instances = &snark.instances[0];
        let KzgAccumulator { lhs, rhs } =
            <LimbsEncoding<LIMBS, BITS> as AccumulatorEncoding<G1Affine, NativeLoader>>::from_repr(
                &agg_instances[..NUM_FE_ACCUMULATOR].iter().collect_vec(),
            )
            .unwrap();
        Some((lhs, rhs))
    } else {
        None
    };
    let compute_proof = AxiomV2ComputeSnark {
        kzg_accumulator,
        compute_results: results.compute_results.clone(),
        proof_transcript: snark.proof,
    };
    AxiomV2ComputeQuery {
        k: k as u8,
        result_len,
        compute_proof: compute_proof.encode().unwrap().into(),
        vkey: partial_vk_output,
    }
}

pub fn get_provider() -> Provider<Http> {
    dotenv().ok();
    Provider::<Http>::try_from(env::var("PROVIDER_URI").expect("PROVIDER_URI not set")).unwrap()
}

/// Constrains and returns a single CircuitValue from a hi-lo pair
///
/// Constrains (hi < r // 2^128) OR (hi == r // 2^128 AND lo < r % 2^128)
/// * `hi`: the high 128 bits of the CircuitValue
/// * `lo`: the low 128 bits of the CircuitValue
pub fn check_hi_lo<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    hi: AssignedValue<F>,
    lo: AssignedValue<F>,
) -> AssignedValue<F> {
    let (hi_max, lo_max) = modulus::<F>().div_mod_floor(&(BigUint::one() << 128));

    //check hi < r // 2**128
    let check_1 = range.is_big_less_than_safe(ctx, hi, hi_max.clone());

    //check (hi == r // 2 ** 128 AND lo < r % 2**128)
    let hi_max_fe = biguint_to_fe::<F>(&hi_max);
    let lo_max_fe = biguint_to_fe::<F>(&lo_max);
    let check_2_hi = range.gate.is_equal(ctx, hi, Constant(hi_max_fe));
    range.range_check(ctx, lo, 128);
    let check_2_lo = range.is_less_than(ctx, lo, Constant(lo_max_fe), 128);
    let check_2 = range.gate.and(ctx, check_2_hi, check_2_lo);

    //constrain (check_1 || check_2) == 1
    let check = range.gate.add(ctx, check_1, check_2);
    range.gate.assert_is_const(ctx, &check, &F::ONE);

    let combined = range
        .gate
        .mul_add(ctx, hi, Constant(range.gate.pow_of_two()[128]), lo);
    combined
}

/// Returns a single CircuitValue from a hi-lo pair
///
/// NOTE: this can fail if the hi-lo pair is greater than the Fr modulus.
/// See `check_hi_lo` for what is constrained.
///
/// * `hi`: the high 128 bits of the CircuitValue
/// * `lo`: the low 128 bits of the CircuitValue
pub fn from_hi_lo<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    hilo: HiLo<AssignedValue<F>>,
) -> AssignedValue<F> {
    check_hi_lo(ctx, range, hilo.hi(), hilo.lo())
}

/// Returns a 256-bit hi-lo pair from a single CircuitValue
///
/// See `check_hi_lo` for what is constrained.
///
/// * `a`: the CircuitValue to split into hi-lo
pub fn to_hi_lo<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    a: AssignedValue<F>,
) -> HiLo<AssignedValue<F>> {
    let a_val = a.value();
    let a_bytes = a_val.to_bytes_le();

    let mut a_lo_bytes = [0u8; 32];
    let mut a_hi_bytes = [0u8; 32];
    a_lo_bytes[..16].copy_from_slice(&a_bytes[..16]);
    a_hi_bytes[..16].copy_from_slice(&a_bytes[16..]);
    let a_lo = F::from_bytes_le(&a_lo_bytes);
    let a_hi = F::from_bytes_le(&a_hi_bytes);

    let a_lo = ctx.load_witness(a_lo);
    let a_hi = ctx.load_witness(a_hi);

    let a_reconstructed = check_hi_lo(ctx, range, a_hi, a_lo);

    ctx.constrain_equal(&a, &a_reconstructed);

    HiLo::from_hi_lo([a_hi, a_lo])
}

pub fn get_logic_output_results_root(output: AxiomV2CircuitOutput) -> LogicOutputResultsRoot {
    let results = output
        .data
        .data_query
        .iter()
        .map(|subquery| SubqueryResult {
            subquery: subquery.subquery_data.clone().0.into(),
            value: Bytes::from(subquery.val.as_bytes().to_vec()),
        })
        .collect_vec();
    let subquery_hashes = results
        .iter()
        .map(|subquery| subquery.keccak())
        .collect_vec();
    let num_subqueries = results.len();
    LogicOutputResultsRoot {
        results,
        subquery_hashes,
        num_subqueries,
    }
}

pub fn check_compute_proof_format(output: AxiomV2CircuitOutput, is_aggregation: bool) {
    let result_len = output.data.compute_results.len();
    let mut instances = output.snark.instances[0].clone();

    //check compute accumulator
    let kzg_accumulators = &output.compute_query.compute_proof[0..NUM_BYTES_ACCUMULATOR];
    if !is_aggregation {
        assert_eq!(kzg_accumulators, &vec![0; NUM_BYTES_ACCUMULATOR]);
    } else {
        //check that accumulator can be deserialized from instances
        let KzgAccumulator { lhs, rhs } =
            <LimbsEncoding<LIMBS, BITS> as AccumulatorEncoding<G1Affine, NativeLoader>>::from_repr(
                &instances[..NUM_FE_ACCUMULATOR].iter().collect_vec(),
            )
            .unwrap();
        assert_eq!(&kzg_accumulators[0..32], lhs.to_bytes().as_ref());
        assert_eq!(&kzg_accumulators[32..64], rhs.to_bytes().as_ref());
        instances.drain(0..NUM_FE_ACCUMULATOR);
    }

    //check compute results
    let compute_results = instances
        .chunks(2)
        .take(result_len)
        .map(|c| decode_hilo_to_h256(HiLo::from_hi_lo([c[0], c[1]])))
        .collect_vec();
    assert_eq!(compute_results, output.data.compute_results);
    assert_eq!(
        &output.compute_query.compute_proof
            [NUM_BYTES_ACCUMULATOR..NUM_BYTES_ACCUMULATOR + (result_len * 2) * 16],
        compute_results
            .iter()
            .flat_map(|a| a.to_fixed_bytes())
            .collect_vec()
            .as_slice()
    );

    //check compute proof transcript
    assert_eq!(
        &output.compute_query.compute_proof[NUM_BYTES_ACCUMULATOR + result_len * 2 * 16..],
        output.snark.proof()
    );
}

pub fn check_compute_query_format(
    output: AxiomV2CircuitOutput,
    params: AxiomCircuitParams,
    vk: VerifyingKey<G1Affine>,
    max_user_outputs: usize,
) {
    let rlc_params = RlcKeccakCircuitParams::from(params.clone()).rlc;
    //check vkey is the same
    let metadata =
        get_metadata_from_protocol(&output.snark.protocol, rlc_params, max_user_outputs).unwrap();
    let onchain_vk = get_onchain_vk_from_vk(&vk, metadata);
    let onchain_vk_h256 = write_onchain_vkey(&onchain_vk).unwrap();
    assert_eq!(output.compute_query.vkey, onchain_vk_h256);

    //check k is correct
    let rlc_keccak_circuit_params = RlcKeccakCircuitParams::from(params.clone());
    assert_eq!(output.compute_query.k, rlc_keccak_circuit_params.k() as u8);

    //check result_len is correct
    assert_eq!(
        output.compute_query.result_len,
        output.data.compute_results.len() as u16
    );

    let results = get_logic_output_results_root(output.clone());
    let (snark, _) = reconstruct_snark_from_compute_query(results, output.compute_query).unwrap();
    assert_eq!(snark.instances, output.snark.instances);
    assert_eq!(snark.proof, output.snark.proof);
}

/// This verifies snark with poseidon transcript and **importantly** also checks the
/// kzg accumulator from the public instances, if `snark` is aggregation circuit
pub fn verify_snark(dk: &KzgDecidingKey<Bn256>, snark: &Snark) -> anyhow::Result<()> {
    let mut transcript =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(snark.proof(), POSEIDON_SPEC.clone());
    let proof: PlonkProof<_, _, SHPLONK> =
        PlonkVerifier::read_proof(dk, &snark.protocol, &snark.instances, &mut transcript)
            .map_err(|_| anyhow!("Failed to read PlonkProof"))?;
    PlonkVerifier::verify(dk, &snark.protocol, &snark.instances, &proof)
        .map_err(|_| anyhow!("PlonkVerifier failed"))?;
    Ok(())
}

/// This function gets query schema from an AxiomV2ComputeQuery
pub fn get_query_schema_from_compute_query(
    compute_query: AxiomV2ComputeQuery,
) -> anyhow::Result<H256> {
    Ok(get_query_schema_hash(
        compute_query.k,
        compute_query.result_len,
        &compute_query.vkey,
    )?)
}

lazy_static! {

    /// TODO: this is also stored in the pinning jsons. We should read it from the pinning if possible.
    /// This commits to the trusted setup used to generate all proving keys.
    /// This MUST be updated whenever the trusted setup is changed.
    pub static ref DK: KzgDecidingKey<Bn256> = serde_json::from_str(r#"
          {
            "_marker": null,
            "g2": "edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19",
            "s_g2": "0016e2a0605f771222637bae45148c8faebb4598ee98f30f20f790a0c3c8e02a7bf78bf67c4aac19dcc690b9ca0abef445d9a576c92ad6041e6ef1413ca92a17",
            "svk": {
              "g": "0100000000000000000000000000000000000000000000000000000000000000"
            }
          }
       "#).unwrap();
}
