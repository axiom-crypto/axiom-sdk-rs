## Usage

```
Run a circuit proving server

Usage: <BIN NAME> [OPTIONS]

Options:
  -d, --data-path <DATA_PATH>  For loading build artifacts [default: data]
  -c, --name <CIRCUIT_NAME>    Name of the circuit metadata file [default: circuit]
  -p, --provider <PROVIDER>    JSON RPC provider URI
      --srs <SRS_PATH>         For specifying custom KZG params directory (defaults to `params`) [default: params]
  -h, --help                   Print help
  -V, --version                Print version
```

## Routes

### Start Proving Job
- Type: POST
- Path: `/start_proving_job`
- Description: Accepts input data in JSON format to initiate a proving job and returns a job ID

### Job Status
- Type: GET
- Path: `/job_status/<id>`
- Description: Retrieves the status of a job by its ID

### Data Query
- Type: GET
- Path: `/data_query/<id>`
- Description: Fetches the data query associated with a job ID as soon as it is ready (before the full circuit output is ready)

### Circuit Output
- Type: GET
- Path: `/circuit_output/<id>`
- Description: Obtains the circuit output for a given job ID
