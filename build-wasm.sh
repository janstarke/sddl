#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cargo install wasm-pack

cargo build --release && (cd sddl-wasm; wasm-pack build --release --target bundler --out-dir ${SCRIPT_DIR}/target/dist/sddl-wasm)