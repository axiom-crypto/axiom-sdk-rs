#!/bin/bash

set -e
set -o pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
export CARGO_HOME=.cargo

# if there's existing .cargo/config.toml, move it to backup file for now
if [[ -f "$CRATE/.cargo/config.toml" ]]; then
  mv -n $CRATE/.cargo/config.toml $CRATE/.cargo/config.toml.bak
fi
if [[ -f ".cargo/config.toml" ]]; then
  mv -n .cargo/config.toml .cargo/config.toml.bak
fi
mkdir -p .cargo
tee .cargo/config.toml << END
[net]
git-fetch-with-cli = true
END

cargo clean
cargo update
cargo fetch


docker build --file sdk/src/Dockerfile.cpu . || exit 1

rm -f .cargo/config.toml
if [[ -f "$CRATE/.cargo/config.toml.bak" ]]; then
  mv -n $CRATE/.cargo/config.toml.bak $CRATE/.cargo/config.toml
fi
if [[ -f ".cargo/config.toml.bak" ]]; then
  mv -n .cargo/config.toml.bak .cargo/config.toml
fi