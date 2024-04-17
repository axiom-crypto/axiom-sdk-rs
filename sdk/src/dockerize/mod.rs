use std::{fs::File, io::Write};

use clap::{command, Parser};

const TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/dockerize/Dockerfile.template.cpu"
));

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct DockerizeCmd {
    #[arg(
        short,
        long = "output-path",
        help = "For loading build artifacts",
        default_value = "Dockerfile.cpu"
    )]
    /// The path to load build artifacts from
    pub output_path: String,
}

pub fn gen_dockerfile(args: Vec<String>, cmd_args: DockerizeCmd) {
    let bin_path = args[0].clone();
    let bin_path_parts: Vec<&str> = bin_path.split(std::path::MAIN_SEPARATOR).collect();
    assert_eq!(
        bin_path_parts[0], "target",
        "The dockerize command only supports the `target` build directory"
    );
    if !(bin_path_parts[1] == "debug" || bin_path_parts[1] == "release") {
        panic!("The dockerize command only supports `debug` or `release` build profiles");
    }
    let is_example = bin_path_parts[2] == "examples";
    let bin_name = if is_example {
        bin_path_parts[3]
    } else {
        bin_path_parts[2]
    };
    let build_flag = if is_example { "--example" } else { "--bin" };
    let build_string = format!("cargo build {} {} --release", build_flag, bin_name);
    let target_path = if bin_path_parts[1] == "debug" {
        bin_path.replace("debug", "release")
    } else {
        bin_path.clone()
    };
    let docker_target_path = format!("/code/{}", target_path);
    let modified_template = TEMPLATE
        .replace("{{build_command}}", &build_string)
        .replace("{{target_path}}", &docker_target_path);

    let mut file = File::create(&cmd_args.output_path).expect("Failed to create Dockerfile");
    file.write_all(modified_template.as_bytes())
        .expect("Failed to write Dockerfile");
    log::info!("Dockerfile written to {}", &cmd_args.output_path);
    log::info!("To build the Dockerfile, run:");
    log::info!("docker build -f {} .", &cmd_args.output_path)
}
