#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DIST_DIR="${SCRIPT_DIR}/target/dist/sddl-wasm"

cargo install wasm-pack

cargo build --release && \
    (cd sddl-wasm; wasm-pack build --release --target web --out-dir "${DIST_DIR}") && \
    echo "created wasm distributable in '${DIST_DIR}'"