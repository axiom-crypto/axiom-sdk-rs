use clap::{Parser, Subcommand};

use crate::{
    cli::types::AxiomCircuitRunnerOptions, dockerize::DockerizeCmd,
    server::types::AxiomComputeServerCmd,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a circuit proving server
    Serve(AxiomComputeServerCmd),
    /// Run keygen and real/mock proving
    Run(AxiomCircuitRunnerOptions),
    /// To generate a Dockerfile for running the circuit binary
    Dockerize(DockerizeCmd),
}

#[macro_export]
macro_rules! axiom_main {
    ($A:ty) => {
        axiom_main!($crate::axiom::AxiomCompute<$A>, $A);
    };
    ($A:ty, $I: ty) => {
        $crate::axiom_compute_prover_server!($A);
        #[tokio::main]
        async fn main() {
            env_logger::init();
            let cli = <$crate::bin::Cli as clap::Parser>::parse();
            match cli.command {
                $crate::bin::Commands::Serve(args) => {
                    let _ = server(args).await;
                }
                $crate::bin::Commands::Run(args) => {
                    let thread = std::thread::spawn(|| {
                        $crate::cli::run_cli_on_scaffold::<$A, $I>(args);
                    });
                    thread.join().unwrap();
                }
                $crate::bin::Commands::Dockerize(args) => {
                    let env_args: Vec<String> = std::env::args().collect();
                    $crate::dockerize::gen_dockerfile(env_args, args);
                }
            }
        }
    };
}
