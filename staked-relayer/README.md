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
source ../.env
cargo run
```

### Options

When using cargo to run the vault, arguments to cargo and the vault are separated by `--`. For example, to pass `--help` to the relayer to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a copy of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables.

```
USAGE:
    cargo run -- [OPTIONS] --bitcoin-rpc-url <bitcoin-rpc-url> --bitcoin-rpc-user <bitcoin-rpc-user> --bitcoin-rpc-pass <bitcoin-rpc-pass>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bitcoin-rpc-pass <bitcoin-rpc-pass>              [env: BITCOIN_RPC_PASS=]
        --bitcoin-rpc-url <bitcoin-rpc-url>                [env: BITCOIN_RPC_URL=]
        --bitcoin-rpc-user <bitcoin-rpc-user>              [env: BITCOIN_RPC_USER=]
        --http-addr <http-addr>
            Address to listen on for JSON-RPC requests [default: [::0]:3030]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<credentials>", "MyUser2": "<credentials>" }`. Credentials should be a
            `0x`-prefixed 64-digit hex string, or a BIP-39 key phrase of 12, 15, 18, 21 or 24 words.
            See `sp_core::from_string_with_seed` for more details

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile [valid values: alice, bob, charlie,
            dave, eve, ferdie]

        --max-batch-size <max-batch-size>
            Max batch size for combined block header submission. [default: 16]

        --oracle-timeout-ms <oracle-timeout-ms>
            Timeout in milliseconds to repeat oracle liveness check [default: 5000]

        --polka-btc-url <polka-btc-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --relay-start-height <relay-start-height>
            Starting height to relay block headers, if not defined use the best height as reported
            by the relay module

        --rpc-cors-domain <rpc-cors-domain>
            Comma separated list of allowed origins [default: *]

        --scan-block-delay <scan-block-delay>
            Delay for checking Bitcoin for new blocks (in seconds) [default: 60]

        --scan-start-height <scan-start-height>
            Starting height for vault theft checks, if not defined automatically start from the
            chain tip

        --status-update-deposit <status-update-deposit>
            Timeout in milliseconds to repeat oracle liveness check [default: 100]
```
