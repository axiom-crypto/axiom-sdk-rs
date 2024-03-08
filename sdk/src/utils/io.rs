use std::{
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
};

use axiom_circuit::{
    axiom_eth::{
        halo2_proofs::{plonk::ProvingKey, SerdeFormat},
        halo2curves::bn256::{Fr, G1Affine},
    },
    scaffold::{AxiomCircuit, AxiomCircuitScaffold},
    types::{AxiomCircuitPinning, AxiomV2CircuitOutput},
};
use ethers::providers::Http;

pub fn write_pk(pk: &ProvingKey<G1Affine>, pk_path: PathBuf) {
    if pk_path.exists() {
        fs::remove_file(&pk_path).unwrap();
    }
    let f =
        File::create(&pk_path).unwrap_or_else(|_| panic!("Could not create file at {pk_path:?}"));
    let mut writer = BufWriter::new(f);
    pk.write(&mut writer, SerdeFormat::RawBytes)
        .expect("writing pkey should not fail");
}

pub fn read_pk<A: AxiomCircuitScaffold<Http, Fr>>(
    pk_path: PathBuf,
    runner: &AxiomCircuit<Fr, Http, A>,
) -> ProvingKey<G1Affine> {
    let params = runner.pinning().params;
    let mut f = File::open(pk_path).expect("pk file should exist");
    ProvingKey::<G1Affine>::read::<_, AxiomCircuit<Fr, Http, A>>(
        &mut f,
        SerdeFormat::RawBytes,
        params,
    )
    .expect("reading pkey should not fail")
}

pub fn write_pinning(pinning: &AxiomCircuitPinning, pinning_path: PathBuf) {
    if pinning_path.exists() {
        fs::remove_file(&pinning_path).unwrap();
    }
    let f = File::create(&pinning_path)
        .unwrap_or_else(|_| panic!("Could not create file at {pinning_path:?}"));
    serde_json::to_writer_pretty(&f, &pinning).expect("writing circuit pinning should not fail");
}

pub fn read_pinning(pinning_path: PathBuf) -> AxiomCircuitPinning {
    let f = File::open(pinning_path).expect("pinning file should exist");
    serde_json::from_reader(f).expect("reading circuit pinning should not fail")
}

pub fn write_output(
    output: AxiomV2CircuitOutput,
    snark_output_path: PathBuf,
    json_output_path: PathBuf,
) {
    let f = File::create(&snark_output_path)
        .unwrap_or_else(|_| panic!("Could not create file at {snark_output_path:?}"));
    bincode::serialize_into(f, &output.snark).expect("Writing SNARK should not fail");
    if json_output_path.exists() {
        fs::remove_file(&json_output_path).unwrap();
    }
    let f = File::create(&json_output_path)
        .unwrap_or_else(|_| panic!("Could not create file at {json_output_path:?}"));
    serde_json::to_writer_pretty(&f, &output).expect("Writing output should not fail");
}
