use std::{
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
};

use axiom_circuit::{
    axiom_eth::{
        halo2_proofs::{
            plonk::{ProvingKey, VerifyingKey},
            SerdeFormat,
        },
        halo2curves::bn256::{Fr, G1Affine},
        snark_verifier_sdk::halo2::aggregation::AggregationCircuit,
        utils::{build_utils::keygen::get_circuit_id, snark_verifier::AggregationCircuitParams},
    },
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{
        AggregationCircuitPinning, AxiomCircuitPinning, AxiomClientCircuitMetadata,
        AxiomV2CircuitOutput,
    },
};
use ethers::providers::Http;
use log::info;
use serde::{de::DeserializeOwned, Serialize};

pub fn write_keygen_output<CoreParams: Serialize>(
    vk: &VerifyingKey<G1Affine>,
    pk: &ProvingKey<G1Affine>,
    pinning: &AxiomCircuitPinning<CoreParams>,
    data_path: PathBuf,
) -> String {
    let circuit_id = get_circuit_id(vk);
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let vk_path = data_path.join(format!("{circuit_id}.vk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    write_vk(vk, vk_path);
    write_pk(pk, pk_path);
    write_pinning(pinning, pinning_path);
    circuit_id
}

pub fn read_pk_and_pinning<A: AxiomCircuitScaffold<Http, Fr>>(
    data_path: PathBuf,
    circuit_id: String,
    runner: &AxiomCircuit<Fr, Http, A>,
) -> (ProvingKey<G1Affine>, AxiomCircuitPinning<A::CoreParams>)
where
    A::CoreParams: DeserializeOwned,
{
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    let pinning = read_pinning(pinning_path);
    let pk = read_pk(pk_path, &runner.clone().use_pinning(pinning.clone()));
    (pk, pinning)
}

pub fn write_agg_keygen_output<CoreParams: Serialize>(
    keygen_output: (
        VerifyingKey<G1Affine>,
        ProvingKey<G1Affine>,
        AggregationCircuitPinning<CoreParams>,
    ),
    data_path: PathBuf,
) -> String {
    let circuit_id = get_circuit_id(&keygen_output.0);
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let vk_path = data_path.join(format!("{circuit_id}.vk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    write_vk(&keygen_output.0, vk_path);
    write_pk(&keygen_output.1, pk_path);
    write_agg_pinning(&keygen_output.2, pinning_path);
    circuit_id
}

pub fn read_agg_pk_and_pinning<CoreParams: DeserializeOwned>(
    data_path: PathBuf,
    circuit_id: String,
) -> (ProvingKey<G1Affine>, AggregationCircuitPinning<CoreParams>) {
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    let pinning = read_agg_pinning(pinning_path);
    let pk = read_agg_pk(pk_path, pinning.params);
    (pk, pinning)
}

pub fn write_vk(vk: &VerifyingKey<G1Affine>, vk_path: PathBuf) {
    if vk_path.exists() {
        fs::remove_file(&vk_path).unwrap();
    }
    let f =
        File::create(&vk_path).unwrap_or_else(|_| panic!("Could not create file at {vk_path:?}"));
    let mut writer = BufWriter::new(f);
    vk.write(&mut writer, SerdeFormat::RawBytes)
        .expect("writing vkey should not fail");
    info!("Wrote verifying key to {:?}", vk_path);
}

pub fn write_keygen_output(
    vk: &VerifyingKey<G1Affine>,
    pk: &ProvingKey<G1Affine>,
    pinning: &AxiomCircuitPinning,
    data_path: PathBuf,
) -> String {
    let circuit_id = get_circuit_id(vk);
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let vk_path = data_path.join(format!("{circuit_id}.vk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    write_vk(vk, vk_path);
    write_pk(pk, pk_path);
    write_pinning(pinning, pinning_path);
    circuit_id
}

pub fn read_pk_and_pinning<A: AxiomCircuitScaffold<Http, Fr>>(
    data_path: PathBuf,
    circuit_id: String,
    runner: &AxiomCircuit<Fr, Http, A>,
) -> (ProvingKey<G1Affine>, AxiomCircuitPinning) {
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    let pinning = read_pinning(pinning_path);
    let pk = read_pk(pk_path, &runner.clone().use_pinning(pinning.clone()));
    (pk, pinning)
}

pub fn write_agg_keygen_output(
    keygen_output: (
        VerifyingKey<G1Affine>,
        ProvingKey<G1Affine>,
        AggregationCircuitPinning,
    ),
    data_path: PathBuf,
) -> String {
    let circuit_id = get_circuit_id(&keygen_output.0);
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let vk_path = data_path.join(format!("{circuit_id}.vk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    write_vk(&keygen_output.0, vk_path);
    write_pk(&keygen_output.1, pk_path);
    write_agg_pinning(&keygen_output.2, pinning_path);
    circuit_id
}

pub fn read_agg_pk_and_pinning(
    data_path: PathBuf,
    circuit_id: String,
) -> (ProvingKey<G1Affine>, AggregationCircuitPinning) {
    let pk_path = data_path.join(format!("{circuit_id}.pk"));
    let pinning_path = data_path.join(format!("{circuit_id}.pinning"));
    let pinning = read_agg_pinning(pinning_path);
    let pk = read_agg_pk(pk_path, pinning.params);
    (pk, pinning)
}

pub fn write_vk(vk: &VerifyingKey<G1Affine>, vk_path: PathBuf) {
    if vk_path.exists() {
        fs::remove_file(&vk_path).unwrap();
    }
    let f =
        File::create(&vk_path).unwrap_or_else(|_| panic!("Could not create file at {vk_path:?}"));
    let mut writer = BufWriter::new(f);
    vk.write(&mut writer, SerdeFormat::RawBytes)
        .expect("writing vkey should not fail");
    info!("Wrote verifying key to {:?}", vk_path);
}

pub fn write_pk(pk: &ProvingKey<G1Affine>, pk_path: PathBuf) {
    if pk_path.exists() {
        fs::remove_file(&pk_path).unwrap();
    }
    let f =
        File::create(&pk_path).unwrap_or_else(|_| panic!("Could not create file at {pk_path:?}"));
    let mut writer = BufWriter::new(f);
    pk.write(&mut writer, SerdeFormat::RawBytes)
        .expect("writing pkey should not fail");
    info!("Wrote proving key to {:?}", pk_path);
}

pub fn write_metadata(metadata: AxiomClientCircuitMetadata, metadata_path: PathBuf) {
    if metadata_path.exists() {
        fs::remove_file(&metadata_path).unwrap();
    }
    let f = File::create(&metadata_path)
        .unwrap_or_else(|_| panic!("Could not create file at {metadata_path:?}"));
    serde_json::to_writer_pretty(&f, &metadata).expect("writing metadata should not fail");
    info!("Wrote circuit metadata to {:?}", metadata_path);
}

pub fn read_metadata(metadata_path: PathBuf) -> AxiomClientCircuitMetadata {
    info!("Reading circuit metadata from {:?}", &metadata_path);
    let f = File::open(metadata_path).expect("metadata file should exist");
    serde_json::from_reader(f).expect("reading circuit metadata should not fail")
}

pub fn read_pk<A: AxiomCircuitScaffold<Http, Fr>>(
    pk_path: PathBuf,
    runner: &AxiomCircuit<Fr, Http, A>,
) -> ProvingKey<G1Affine> {
    let params = runner.pinning().params;
    info!("Reading proving key from {:?}", &pk_path);
    let mut f = File::open(pk_path).expect("pk file should exist");
    ProvingKey::<G1Affine>::read::<_, AxiomCircuit<Fr, Http, A>>(
        &mut f,
        SerdeFormat::RawBytes,
        params,
    )
    .expect("reading pkey should not fail")
}

pub fn read_agg_pk(pk_path: PathBuf, params: AggregationCircuitParams) -> ProvingKey<G1Affine> {
    info!("Reading agg proving key from {:?}", pk_path);
    let mut f = File::open(pk_path).expect("pk file should exist");
    ProvingKey::<G1Affine>::read::<_, AggregationCircuit>(&mut f, SerdeFormat::RawBytes, params)
        .expect("reading pkey should not fail")
}

pub fn write_pinning<CoreParams: Serialize>(
    pinning: &AxiomCircuitPinning<CoreParams>,
    pinning_path: PathBuf,
) {
    if pinning_path.exists() {
        fs::remove_file(&pinning_path).unwrap();
    }
    let f = File::create(&pinning_path)
        .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
    serde_json::to_writer_pretty(&f, &pinning).expect("writing circuit pinning should not fail");
    info!("Wrote circuit pinning to {:?}", pinning_path);
}

pub fn write_agg_pinning<CoreParams: Serialize>(
    pinning: &AggregationCircuitPinning<CoreParams>,
    pinning_path: PathBuf,
) {
    if pinning_path.exists() {
        fs::remove_file(&pinning_path).unwrap();
    }
    let f = File::create(&pinning_path)
        .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
    serde_json::to_writer_pretty(&f, &pinning).expect("writing circuit pinning should not fail");
    info!("Wrote circuit pinning to {:?}", pinning_path);
}

pub fn read_pinning<CoreParams: DeserializeOwned>(
    pinning_path: PathBuf,
) -> AxiomCircuitPinning<CoreParams> {
    info!("Reading circuit pinning from {:?}", &pinning_path);
    let f = File::open(pinning_path).expect("pinning file should exist");
    serde_json::from_reader(f).expect("reading circuit pinning should not fail")
}

pub fn read_agg_pinning<CoreParams: DeserializeOwned>(
    pinning_path: PathBuf,
) -> AggregationCircuitPinning<CoreParams> {
    info!("Reading agg circuit pinning from {:?}", &pinning_path);
    let f = File::open(pinning_path).expect("pinning file should exist");
    serde_json::from_reader(f).expect("reading circuit pinning should not fail")
}

pub fn write_output(
    output: AxiomV2CircuitOutput,
    snark_output_path: PathBuf,
    json_output_path: PathBuf,
) {
    info!("Writing SNARK to {:?}", &snark_output_path);
    let f = File::create(&snark_output_path)
        .unwrap_or_else(|_| panic!("Could not create file at {snark_output_path:?}"));
    bincode::serialize_into(f, &output.snark).expect("Writing SNARK should not fail");
    if json_output_path.exists() {
        fs::remove_file(&json_output_path).unwrap();
    }
    info!("Writing JSON output to {:?}", &json_output_path);
    let f = File::create(&json_output_path)
        .unwrap_or_else(|_| panic!("Could not create file at {json_output_path:?}"));
    serde_json::to_writer_pretty(&f, &output).expect("Writing output should not fail");
}
