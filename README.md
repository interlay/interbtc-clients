<p align="center">
  <a href="https://gitlab.com/interlay/polkabtc-clients">
    <img src="media/polka_btc.png">
  </a>

  <h2 align="center">PolkaBTC Clients</h2>

  <p align="center">
    Faucet, Oracle, Vault & Staked Relayer
  </p>
</p>

_This project is currently under active development_.

## Prerequisites

Download and start [Bitcoin Core](https://bitcoin.org/en/bitcoin-core/):

```
bitcoind -regtest -server
```

Build and run the [BTC Parachain](https://github.com/interlay/btc-parachain):

```
git clone git@gitlab.com:interlay/btc-parachain.git
cd btc-parachain
cargo run --release -- --dev
```

Generate an address and mine some blocks:

```bash
address=`bitcoin-cli -regtest getnewaddress`
bitcoin-cli -regtest generatetoaddress 101 $address
```

> Note: This may require `rpcuser` and `rpcpassword` to be set.

Alternatively run `bitcoin-cli` from docker: 

```bash
docker run --network host --entrypoint bitcoin-cli ruimarinho/bitcoin-core:0.20 -regtest -rpcuser=rpcuser -rpcpassword=rpcpassword ${COMMAND}
```

### Development

Building requires Rust `nightly`. Run the following commands to set it up:

```
rustup toolchain install nightly-2021-03-15
rustup default nightly-2021-03-15
```

## Getting Started

### Oracle

The BTC Parachain requires a price oracle to calculate collateralization rates, for local development we can run this client
to automatically update the exchange rate at a pre-determined time interval.

```bash
cargo run --bin oracle
```

### Staked Relayer

The [Staked Relayer](./staked-relayer/README.md) client is responsible for submitting Bitcoin block headers to the BTC Parachain.

```bash
source .env
cargo run --bin staked-relayer -- --http-addr '[::0]:3030'
```

### Testdata

To interact with the BTC Parachain directly, use the [testdata-gen](./testdata-gen/README.md) client.

```bash
source .env
cargo run --bin testdata-gen -- --keyring bob set-exchange-rate --exchange-rate 1
```

### Vault

The [Vault](./vault/README.md) client is used to intermediate assets between Bitcoin and the BTC Parachain.

```bash
source .env
cargo run --bin vault
```

<p align="center">
  <a href="https://web3.foundation/grants/">
    <img src="media/web3_grants.png">
  </a>
</p>

## Troubleshooting

**Too many open files**

On `cargo test` the embedded parachain node in the integration tests can consume a lot of resources. Currently the best workaround is to increase the resource limits of the current user.

Use `ulimit -a` to list the current resource limits. To increase the maximum number of files set `ulimit -n 4096` or some other reasonable limit. 
