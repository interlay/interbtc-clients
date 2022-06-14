<p align="center">
  <a href="https://github.com/interlay/interbtc-clients">
    <img alt="interBTC Clients" src="media/banner.jpg">
  </a>
  <h2 align="center">interBTC Clients</h2>

  <p align="center">
    Faucet, Oracle & Vault / Relayer
  </p>
</p>

_This project is currently under active development_.

## Getting started

### Prerequisites

```
curl https://sh.rustup.rs -sSf | sh
```

Please also install the following dependencies:

- `cmake`
- `clang` (>=10.0.0)
- `clang-dev`
- `libc6-dev`
- `libssl-dev`
- `pkg-config` (on Ubuntu)

### Installation

#### Faucet

The testnet may use a faucet to allow users and vaults to self-fund up to a daily limit.

To start the Faucet follow the instructions contained in the [Faucet README](./faucet/README.md).

#### Oracle

The interBTC bridge requires a price oracle to calculate collateralization rates, for local development we can run this client
to automatically update the exchange rate at a pre-determined time interval.

To start the Oracle follow the instructions contained in the [Oracle README](./oracle/README.md).

#### Vault

The vault client is used to intermediate assets between Bitcoin and the BTC Parachain.
It is also capable of submitting Bitcoin block headers to the BTC Parachain.

To start the Vault follow the instructions contained in the [Vault README](./vault/README.md).

### Development

Building requires a specific rust toolchain and nightly compiler version. The
requirements are specified in the [./rust-toolchain.toml](./rust-toolchain.toml)
[override file](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file).

Running `rustup show` from the root directory of this repo should be enough to
set up the toolchain and you can inspect the output to verify that it matches
the version specified in the override file.

Use the following command to fetch the newest metadata from a live chain:

```shell
curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"state_getMetadata", "id": 1}' localhost:9933 | jq .result | cut -d '"' -f 2 | xxd -r -p > runtime/metadata.scale
```

To build, one of the following mutually-exclusive features must be specified:
- parachain-metadata-interlay
- parachain-metadata-kintsugi
- parachain-metadata-interlay-testnet
- parachain-metadata-kintsugi-testnet
- standalone-metadata

The default command for building the clients, assuming a standalone chain, is:
```shell
cargo build --features=standalone-metadata
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
