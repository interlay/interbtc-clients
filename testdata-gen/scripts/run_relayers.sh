#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

NUM_RELAYERS=${NUM_RELAYERS:-5}

RELAYER_AMOUNT=${RELAYER_AMOUNT:-1000000000000} # 100 DOT
RELAYER_STAKE=${RELAYER_STAKE:-100} # 0.00000001 DOT

BTC_PARACHAIN_RPC=${BTC_PARACHAIN_RPC:-"ws://localhost:9944"}

RELAYER_CLIENT_BIN=${RELAYER_CLIENT_BIN:-"${DIR}/../../target/debug/staked-relayer"}
TESTDATA_CLIENT_BIN=${TESTDATA_CLIENT_BIN:-"${DIR}/../../target/debug/testdata-gen"}

declare -A secrets
declare -A accounts

keyFile=$(mktemp)

function finish {
  rm $keyFile
  kill -- -$$
}
trap finish EXIT

# populate keyfile
for i in $(seq 1 $NUM_RELAYERS); do
    RELAYER_NAME="relayer-${i}"

    SECRET_KEY=$(subkey generate --output-type json)
    SECRET_PHRASE=$(echo ${SECRET_KEY} | jq .secretPhrase)
    secrets[${RELAYER_NAME}]=${SECRET_PHRASE}

    ACCOUNT_ID=$(echo ${SECRET_KEY} | jq -r .ss58Address)
    accounts[${RELAYER_NAME}]=${ACCOUNT_ID}
    echo "${RELAYER_NAME}=${ACCOUNT_ID}"
done

for i in "${!secrets[@]}"
do
    echo "\"$i\""
    echo "${secrets[$i]}"
done | 
jq -n 'reduce inputs as $i ({}; . + { ($i): input })' > $keyFile

${TESTDATA_CLIENT_BIN} --keyring alice --polka-btc-url ${BTC_PARACHAIN_RPC} \
    fund-accounts --accounts ${accounts[@]} --amount ${RELAYER_AMOUNT}

for i in $(seq 1 $NUM_RELAYERS); do
    RELAYER_NAME="relayer-${i}"
    echo "Starting ${RELAYER_NAME}"

    ${RELAYER_CLIENT_BIN} \
        --polka-btc-url ${BTC_PARACHAIN_RPC} \
        --auto-register-with-stake ${RELAYER_STAKE} \
        --keyfile $keyFile \
        --keyname ${RELAYER_NAME} &

done

wait