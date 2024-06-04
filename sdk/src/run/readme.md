## Usage

```
Run keygen and real/mock proving

Usage: <BIN NAME> [OPTIONS] <COMMAND>

Commands:
  mock    Run the mock prover
  keygen  Generate new proving & verifying keys
  run     Generate an Axiom compute query
  help    Print this message or the help of the given subcommand(s)

Options:
  -k, --degree <DEGREE>          To determine the size of your circuit (12..25)
  -p, --provider <PROVIDER>      JSON RPC provider URI
  -i, --input <INPUT_PATH>       JSON inputs to feed into your circuit
  -n, --name <NAME>              Name of the output metadata file [default: circuit]
  -d, --data-path <DATA_PATH>    For saving build artifacts [default: data]
  -c, --config <CONFIG>          For specifying custom circuit parameters
      --srs <SRS>                For specifying custom KZG params directory
      --aggregate                Whether to aggregate the output [default: false]
      --auto-config-aggregation  Whether to aggregate the output [default: false]
  -s, --to-stdout                (witness-gen only) Output to stdout (true) or json (false) [default: false]
  -h, --help                     Print help
  -V, --version                  Print version
```