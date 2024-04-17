# axiom-sdk

## Usage

See [./examples/account_age.rs](./examples/account_age.rs) for an example Axiom compute circuit. To run the `account_age` circuit:

```
cargo run --example account_age -- --input data/account_age_input.json -k 12 -p <PROVIDER_URI> <CMD>
```

where `PROVIDER_URI` is a JSON-RPC URL, and `CMD` is `mock`, `prove`, `keygen`, or `run`.


## CLI 

```Usage: account_age <COMMAND>

Commands:
  serve  Run a circuit proving server
  run    Run keygen and real/mock proving
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Run

```
Run keygen and real/mock proving

Usage: account_age run [OPTIONS] <COMMAND>

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
      --srs <SRS>                For specifying custom KZG params directory [default: params]
      --aggregate                Whether to aggregate the output (defaults to false)
      --auto-config-aggregation  Whether to aggregate the output (defaults to false)
  -h, --help                     Print help
  -V, --version                  Print version
```


### Serve

```
Run a circuit proving server

Usage: account_age serve [OPTIONS]

Options:
  -d, --data-path <DATA_PATH>  For loading build artifacts [default: data]
  -c, --name <CIRCUIT_NAME>    Name of the circuit metadata file [default: circuit]
  -p, --provider <PROVIDER>    JSON RPC provider URI
      --srs <SRS_PATH>         For specifying custom KZG params directory (defaults to `params`) [default: params]
  -h, --help                   Print help
  -V, --version                Print version
```