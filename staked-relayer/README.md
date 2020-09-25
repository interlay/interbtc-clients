# PolkaBTC Staked Relayer

## Responsibilities

- Receive block headers from [Bitcoin Core](https://github.com/bitcoin/bitcoin) 
- Submit block headers to the [PolkaBTC Parachain](https://github.com/interlay/BTC-Parachain)
- Register and stake DOT collateral
- Participate in core governance procedures
- Monitor the BTC addresses of vaults to report BTC thefts
- Monitor and report under-collateralised vaults
- Monitor and report when the Oracle is offline

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

Run the staked relayer client:

```
source .env
cargo run
```