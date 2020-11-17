#!/bin/bash

COLLATERAL=100000000
set -e
echo "hallo ${BITCOIN_RPC_USER}"
ALICE_ADDRESS=$(bitcoin-cli -regtest -rpcuser=${BITCOIN_RPC_USER} -rpcpassword=${BITCOIN_RPC_PASS} getnewaddress)
cargo run --bin testdata-gen -- --keyring alice register-vault --btc-address ${ALICE_ADDRESS} --collateral ${COLLATERAL}

BOB_ADDRESS=$(bitcoin-cli -regtest -rpcuser=${BITCOIN_RPC_USER} -rpcpassword=${BITCOIN_RPC_PASS} getnewaddress)
cargo run --bin testdata-gen -- --keyring bob register-vault --btc-address ${BOB_ADDRESS} --collateral ${COLLATERAL}

CHARLIE_ADDRESS=$(bitcoin-cli -regtest -rpcuser=${BITCOIN_RPC_USER} -rpcpassword=${BITCOIN_RPC_PASS} getnewaddress)
cargo run --bin testdata-gen -- --keyring charlie register-vault --btc-address ${CHARLIE_ADDRESS} --collateral ${COLLATERAL}