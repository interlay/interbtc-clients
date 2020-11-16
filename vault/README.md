# PolkaBTC Vault

## Responsibilities

- Register
  - Lock DOT collateral in Vault Registry
  - Submit current BTC address to Vault Registry
- Redeem
  - Listen for redeem events
  - Send BTC transaction to user
  - Get BTC transaction inclusion proof and raw tx
  - Execute redeem with corresponding redeem id, tx inclusion proof and raw tx
- Collateral balance
  - Observe collateralization rate in Vault Registry
  - Withdraw/lock collateral to keep rate consistent
- Replace
  - Request Replace
  - Execute Replace

## Prerequisites

Download and start [Bitcoin Core](https://bitcoin.org/en/bitcoin-core/):

```
bitcoind -testnet -server
```

Build and run the [PolkaBTC Parachain](https://gitlab.com/interlay/btc-parachain):

```
git clone git@gitlab.com:interlay/btc-parachain.git
cd btc-parachain
cargo run --release -- --dev
```

## Getting Started

Run the vault client:

```
source .env
cargo run
```

For all command line options, see:

```
source .env
cargo run -- --help
```