#!/bin/bash

# bitcoind -regtest -server &>/dev/null &
# pid=$!

docker run -d --name bitcoind --network host --entrypoint bitcoind ruimarinho/bitcoin-core:0.20 -regtest -rpcuser=rpcuser -rpcpassword=rpcpassword
sleep 1

function finish {
  # kill $pid
  docker stop bitcoind
  docker rm bitcoind
}
trap finish EXIT

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${DIR}/../"

export BITCOIN_RPC_URL="http://localhost:18443"
export BITCOIN_RPC_USER="rpcuser"
export BITCOIN_RPC_PASS="rpcpassword"

cargo test --test '*' --features uses-bitcoind -- --test-threads=1 --nocapture