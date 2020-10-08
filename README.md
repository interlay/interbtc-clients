<p align="center">
  <a href="https://gitlab.com/interlay/polkabtc-clients">
    <img src="media/polka_btc.png">
  </a>

  <h2 align="center">PolkaBTC Clients</h2>

  <p align="center">
    Vault & Staked Relayers
  </p>
</p>

_This project is currently under active development_.

## Prerequisites

You need to have Rust installed.

Building requires `nightly`. Run the following commands to set it up:

```
rustup toolchain install nightly-2020-10-01
rustup default nightly-2020-10-01
```

## Getting Started

Clone the repository.

```bash
git clone git@gitlab.com:interlay/polkabtc-clients.git
```

Clone the submodules.

```bash
cd polkabtc-clients 
git submodule update --init --recursive
```

Build the project.

```bash
cargo build
```

<p align="center">
  <a href="https://web3.foundation/grants/">
    <img src="media/web3_grants.png">
  </a>
</p>
