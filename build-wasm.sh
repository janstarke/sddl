#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DIST_DIR="${SCRIPT_DIR}/target/dist/sddl4web"

cargo install wasm-pack

cargo build --release && \
    (cd sddl4web; wasm-pack build --release --target bundler --out-dir "${DIST_DIR}") && \
    echo "created wasm distributable in '${DIST_DIR}'"