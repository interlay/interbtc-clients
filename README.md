<p align="center">
  <a href="https://gitlab.com/interlay/polkabtc-clients">
    <img src="media/polka_btc.png">
  </a>

  <h2 align="center">PolkaBTC Clients</h2>

  <p align="center">
    Oracle, Vault & Staked Relayer
  </p>
</p>

_This project is currently under active development_.

## Prerequisites

Before running the client software, please start Bitcoin Core and the PolkaBTC Parachain.

This repository contains a docker-compose file which starts PolkaBTC in `--dev` mode and
a Bitcoin daemon in `-regtest` mode.

```bash
docker-compose up
```

Run the following command to generate an address and mine some blocks:

```bash
address=`bitcoin-cli -regtest getnewaddress`
bitcoin-cli -regtest generatetoaddress 10 $address
```

> Note: This may require `rpcuser` and `rpcpassword` to be set.

Alternatively run `bitcoin-cli` from docker: 

```bash
docker run --network host --entrypoint bitcoin-cli ruimarinho/bitcoin-core:0.20 -regtest -rpcuser=rpcuser -rpcpassword=rpcpassword ${COMMAND}
```

### Development

Building requires Rust `nightly`. Run the following commands to set it up:

```
rustup toolchain install nightly-2020-10-01
rustup default nightly-2020-10-01
```

## Getting Started

### Oracle

PolkaBTC requires a price oracle to calculate collateralization rates, for local development we can run this client
to automatically update the exchange rate at a pre-determined time interval.

```bash
cargo run --bin oracle
```

### Staked Relayer

The [Staked Relayer](./staked-relayer/README.md) client is responsible for submitting Bitcoin block headers to PolkaBTC and reporting on various error states.

```bash
source .env
cargo run --bin staked-relayer -- --http-addr '[::0]:3030'
```

### Testdata

To interact with PolkaBTC directly, use the [testdata-gen](./testdata-gen/README.md) client.

```bash
source .env
cargo run --bin testdata-gen -- --keyring bob set-exchange-rate --exchange-rate 1
```

### Vault

The [Vault](./vault/README.md) client is used to intermediate assets between Bitcoin and PolkaBTC.

```bash
source .env
cargo run --bin vault
```

<p align="center">
  <a href="https://web3.foundation/grants/">
    <img src="media/web3_grants.png">
  </a>
</p>
