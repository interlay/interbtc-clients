#!/bin/bash

COLLATERAL=100000000

ALICE_ADDRESS=$(bitcoin-cli -regtest getnewaddress)
cargo run -p testdata-gen -- --keyring alice register-vault --btc-address ${ALICE_ADDRESS} --collateral ${COLLATERAL}

BOB_ADDRESS=$(bitcoin-cli -regtest getnewaddress)
cargo run -p testdata-gen -- --keyring bob register-vault --btc-address ${BOB_ADDRESS} --collateral ${COLLATERAL}

CHARLIE_ADDRESS=$(bitcoin-cli -regtest getnewaddress)
cargo run -p testdata-gen -- --keyring charlie register-vault --btc-address ${CHARLIE_ADDRESS} --collateral ${COLLATERAL}