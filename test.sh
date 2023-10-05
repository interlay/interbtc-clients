#!/bin/bash

export RUST_LOG="info,regalloc=warn"
export BITCOIN_RPC_URL="http://127.0.0.1:18443"
export BITCOIN_RPC_USER="rpcuser"
export BITCOIN_RPC_PASS="rpcpassword"
export ELECTRS_URL="http://localhost:3002"
sudo docker-compose up -d bitcoind bitcoin-cli electrs
cargo test --release --workspace --features parachain-metadata-kintsugi --features uses-bitcoind -- --nocapture
