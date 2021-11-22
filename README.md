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

#### Oracle

The interBTC bridge requires a price oracle to calculate collateralization rates, for local development we can run this client
to automatically update the exchange rate at a pre-determined time interval.

To start the Oracle follow the instructions contained in the [Oracle README](./oracle/README.md).

#### Vault

The [Vault](./vault/README.md) client is used to intermediate assets between Bitcoin and the BTC Parachain.
It is also capable of submitting Bitcoin block headers to the BTC Parachain.

To start the Vault follow the instructions contained in the [Vault README](./vault/README.md).

### Development

Building requires a specific rust toolchain and nightly compiler version. The
requirements are specified in the [./rust-toolchain.toml](./rust-toolchain.toml)
[override file](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file).

Running `rustup show` from the root directory of this repo should be enough to
set up the toolchain and you can inspect the output to verify that it matches
the version specified in the override file.


<p align="center">
  <a href="https://web3.foundation/grants/">
    <img src="media/web3_grants.png">
  </a>
</p>

## Troubleshooting

**Too many open files**

On `cargo test` the embedded parachain node in the integration tests can consume a lot of resources. Currently the best workaround is to increase the resource limits of the current user.

Use `ulimit -a` to list the current resource limits. To increase the maximum number of files set `ulimit -n 4096` or some other reasonable limit. 
