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

Clone the `relayer-core` package.

```bash
git clone git@gitlab.com:interlay/relayer-core.git
```

Clone the `substrate-subxt` package.

```bash
git clone git@github.com:paritytech/substrate-subxt.git
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
curl -fX GET 127.0.0.1:3030/best_block
```

<p align="center">
  <a href="https://web3.foundation/grants/">
    <img src="media/web3_grants.png">
  </a>
</p>
