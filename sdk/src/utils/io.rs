use std::{
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
};

use axiom_circuit::{
    axiom_eth::{
        halo2_proofs::{plonk::ProvingKey, SerdeFormat},
        halo2curves::bn256::{Fr, G1Affine},
        snark_verifier_sdk::halo2::aggregation::AggregationCircuit,
        utils::snark_verifier::AggregationCircuitParams,
    },
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{AggregationCircuitPinning, AxiomCircuitPinning, AxiomV2CircuitOutput},
};
use ethers::providers::Http;
use log::info;

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

pub fn write_pinning(pinning: &AxiomCircuitPinning, pinning_path: PathBuf) {
    if pinning_path.exists() {
        fs::remove_file(&pinning_path).unwrap();
    }
    let f = File::create(&pinning_path)
        .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
    serde_json::to_writer_pretty(&f, &pinning).expect("writing circuit pinning should not fail");
    info!("Wrote circuit pinning to {:?}", pinning_path);
}

pub fn write_agg_pinning(pinning: &AggregationCircuitPinning, pinning_path: PathBuf) {
    if pinning_path.exists() {
        fs::remove_file(&pinning_path).unwrap();
    }
    let f = File::create(&pinning_path)
        .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
    serde_json::to_writer_pretty(&f, &pinning).expect("writing circuit pinning should not fail");
    info!("Wrote circuit pinning to {:?}", pinning_path);
}

pub fn read_pinning(pinning_path: PathBuf) -> AxiomCircuitPinning {
    info!("Reading circuit pinning from {:?}", &pinning_path);
    let f = File::open(pinning_path).expect("pinning file should exist");
    serde_json::from_reader(f).expect("reading circuit pinning should not fail")
}

pub fn read_agg_pinning(pinning_path: PathBuf) -> AggregationCircuitPinning {
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
