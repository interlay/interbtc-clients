# Vault

## Responsibilities

- Register
  - Lock collateral in Vault Registry
  - Submit master public key to Vault Registry
- Issue
  - Detect and execute pending issue requests
- Redeem
  - Listen for redeem events
  - Send BTC transaction to user
  - Get BTC transaction inclusion proof and raw tx
  - Execute redeem with corresponding redeem id, tx inclusion proof and raw tx
- Refund
  - Reimburse users who overpay on issue
- Collateral balance
  - Observe collateralization rate in Vault Registry
  - Withdraw / deposit collateral to keep rate consistent
- Replace
  - Request Replace
  - Execute Replace

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

## Getting Started

The basic command to run the vault client:

```
source ../.env
cargo run
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the vault to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a copy of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables. 

```
USAGE:
    vault [FLAGS] [OPTIONS] --bitcoin-rpc-url <bitcoin-rpc-url> --bitcoin-rpc-user <bitcoin-rpc-user> --bitcoin-rpc-pass <bitcoin-rpc-pass>

FLAGS:
    -h, --help                              Prints help information
        --no-api                            Don't run the RPC API
        --no-auto-replace                   Opt out of participation in replace requests
        --no-issue-execution                Don't try to execute issues
        --no-startup-collateral-increase    Don't check the collateralization rate at startup
    -V, --version                           Prints version information

OPTIONS:
        --auto-register-with-collateral <auto-register-with-collateral>
            Automatically register the vault with the given amount of collateral and a newly
            generated address

        --auto-register-with-faucet-url <auto-register-with-faucet-url>
            Automatically register the vault with the collateral received from the faucet and a
            newly generated address. The parameter is the URL of the faucet

        --bitcoin-connection-timeout-ms <bitcoin-connection-timeout-ms>
            Timeout in milliseconds to wait for connection to bitcoin-core [default: 60000]

        --bitcoin-rpc-pass <bitcoin-rpc-pass>
            [env: BITCOIN_RPC_PASS=rpcpassword]

        --bitcoin-rpc-url <bitcoin-rpc-url>
            [env: BITCOIN_RPC_URL=http://localhost:18443]

        --bitcoin-rpc-user <bitcoin-rpc-user>
            [env: BITCOIN_RPC_USER=rpcuser]

        --btc-confirmations <btc-confirmations>
            How many bitcoin confirmations to wait for. If not specified, the parachain settings
            will be used (recommended)

        --btc-parachain-url <btc-parachain-url>
            Parachain websocket URL [default: ws://127.0.0.1:9944]

        --collateral-timeout-ms <collateral-timeout-ms>
            Timeout in milliseconds to repeat collateralization checks [default: 5000]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile

        --logging-format <logging-format>
            Logging output format [default: full]

        --max-collateral <max-collateral>
            Maximum total collateral to keep the vault securely collateralized [default: 1000000]

        --max-concurrent-requests <max-concurrent-requests>
            Maximum number of concurrent requests

        --max-notifs-per-subscription <max-notifs-per-subscription>
            Maximum notification capacity for each subscription

        --network <network>
            Bitcoin network type for address encoding [default: regtest]

        --polka-btc-connection-timeout-ms <polka-btc-connection-timeout-ms>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --restart-policy <restart-policy>
            Restart or stop on error [default: always]

        --rpc-cors-domain <rpc-cors-domain>
            Comma separated list of allowed origins [default: *]

        --telemetry-url <telemetry-url>                                        Telemetry endpoint
```
