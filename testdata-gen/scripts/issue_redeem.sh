#!/bin/bash

cargo run -p testdata-gen -- --keyring bob set-exchange-rate --exchange-rate 1

cargo run -p testdata-gen -- --keyring alice request-issue --issue-amount 1000000 --vault bob

ALICE_ADDRESS=$(bitcoin-cli -regtest getnewaddress)
REDEEM_ID=$(cargo run -p testdata-gen -- --keyring alice request-redeem --redeem-amount 10000 --btc-address ${ALICE_ADDRESS} --vault bob)

cargo run -p testdata-gen -- --keyring bob execute-redeem --redeem-id ${REDEEM_ID}
