#!/bin/bash

# cargo run -p testdata-gen -- --keyring bob set-exchange-rate --exchange-rate 1
# cargo run -p testdata-gen -- --keyring alice request-issue --issue-amount 10000 --vault bob

REPLACE_ID=$(cargo run -p testdata-gen -- --keyring charlie request-replace --replace-amount 100000)
cargo run -p testdata-gen -- --keyring charlie accept-replace --replace-id ${REPLACE_ID} --collateral 100000
cargo run -p testdata-gen -- --keyring bob execute-replace --replace-id ${REPLACE_ID}