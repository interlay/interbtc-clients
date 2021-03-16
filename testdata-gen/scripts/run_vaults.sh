#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

NUM_VAULTS=${NUM_VAULTS:-5}

VAULT_AMOUNT=${VAULT_AMOUNT:-1001000000000000} # 100,100 DOT
VAULT_COLLATERAL=${VAULT_COLLATERAL:-1000000000000000} # 100,000 DOT

BTC_PARACHAIN_RPC=${BTC_PARACHAIN_RPC:-"ws://localhost:9944"}

VAULT_CLIENT_BIN=${VAULT_CLIENT_BIN:-"${DIR}/../../target/debug/vault"}
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
for i in $(seq 1 $NUM_VAULTS); do
    VAULT_NAME="vault-${i}"

    SECRET_KEY=$(subkey generate --output-type json)
    SECRET_PHRASE=$(echo ${SECRET_KEY} | jq .secretPhrase)
    secrets[${VAULT_NAME}]=${SECRET_PHRASE}

    ACCOUNT_ID=$(echo ${SECRET_KEY} | jq -r .ss58Address)
    accounts[${VAULT_NAME}]=${ACCOUNT_ID}
    echo "${VAULT_NAME}=${ACCOUNT_ID}"
done

for i in "${!secrets[@]}"
do
    echo "\"$i\""
    echo "${secrets[$i]}"
done | 
jq -n 'reduce inputs as $i ({}; . + { ($i): input })' > $keyFile

${TESTDATA_CLIENT_BIN} --keyring alice --polka-btc-url ${BTC_PARACHAIN_RPC} \
    fund-accounts --accounts ${accounts[@]} --amount ${VAULT_AMOUNT}

for i in $(seq 1 $NUM_VAULTS); do
    VAULT_NAME="vault-${i}"
    echo "Starting ${VAULT_NAME}"

    ${VAULT_CLIENT_BIN} \
        --polka-btc-url ${BTC_PARACHAIN_RPC} \
        --auto-register-with-collateral ${VAULT_COLLATERAL} \
        --keyfile $keyFile \
        --keyname ${VAULT_NAME} \
        --network regtest &

done

wait