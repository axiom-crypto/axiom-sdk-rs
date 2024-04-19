use std::{fs::File, path::Path};

use axiom_circuit::axiom_eth::{
    halo2_proofs::poly::kzg::commitment::ParamsKZG, halo2curves::bn256::Bn256,
    utils::build_utils::keygen::read_srs_from_dir,
};

pub mod io;

pub fn read_srs_from_dir_or_install(params_dir: &Path, k: u32) -> ParamsKZG<Bn256> {
    if !params_dir.exists() {
        std::fs::create_dir_all(params_dir).expect("Failed to create SRS path directory");
    }
    let srs_file_path = params_dir.join(format!("kzg_bn254_{}.srs", k));
    if !srs_file_path.exists() {
        log::info!("SRS file not found at: {}", srs_file_path.display());
        log::info!("Downloading SRS file...");

        let srs_url = format!(
            "https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_{}.srs",
            k
        );
        let response = reqwest::blocking::get(srs_url).expect("Failed to download SRS file");

        if response.status().is_success() {
            let mut file = File::create(&srs_file_path).expect("Failed to create file for SRS");
            let content = response.bytes().expect("Failed to read response bytes");
            std::io::copy(&mut content.as_ref(), &mut file).expect("Failed to write SRS file");
            log::info!("SRS file downloaded successfully.");
        } else {
            panic!(
                "Failed to download SRS file. HTTP Error: {}",
                response.status()
            );
        }
    }
    read_srs_from_dir(params_dir, k).expect("Unable to read SRS")
}
