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

- Receive block headers from [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- Submit block headers to the [BTC Parachain](https://github.com/interlay/interbtc)
- Monitor the BTC addresses of vaults to report BTC thefts

## Prerequisites

Download and start [Bitcoin Core](https://bitcoin.org/en/bitcoin-core/):

```
bitcoind -regtest -server
```

Build and run the [interBTC Parachain](https://github.com/interlay/interbtc):

```
git clone git@gitlab.com:interlay/interbtc.git
cargo run --bin interbtc-standalone -- --dev --tmp
```

## Getting Started

The basic command to run the vault client:

```
source ../.env
cargo run --bin vault --features standalone-metadata
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the vault to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run --bin vault --features standalone-metadata -- --help
```

For convenience, a copy of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables. 

```
USAGE:
    vault [FLAGS] [OPTIONS] --bitcoin-rpc-url <BITCOIN_RPC_URL> --bitcoin-rpc-user <BITCOIN_RPC_USER> --bitcoin-rpc-pass <BITCOIN_RPC_PASS>

FLAGS:
    -h, --help                      Print help information
        --no-api                    Don't run the RPC API
        --no-auto-refund            Don't refund overpayments
        --no-auto-replace           Opt out of participation in replace requests
        --no-bitcoin-block-relay    Don't relay bitcoin block headers
        --no-issue-execution        Don't try to execute issues
        --no-vault-theft-report     Don't monitor vault thefts
    -V, --version                   Print version information

OPTIONS:
        --auto-register-with-collateral <AUTO_REGISTER_WITH_COLLATERAL>
            Automatically register the vault with the given amount of collateral and a newly
            generated address

        --auto-register-with-faucet-url <AUTO_REGISTER_WITH_FAUCET_URL>
            Automatically register the vault with the collateral received from the faucet and a
            newly generated address. The parameter is the URL of the faucet

        --bitcoin-connection-timeout-ms <BITCOIN_CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to bitcoin-core [default: 60000]

        --bitcoin-poll-interval-ms <BITCOIN_POLL_INTERVAL_MS>
            Timeout in milliseconds to poll Bitcoin [default: 6000]

        --bitcoin-relay-confirmations <BITCOIN_RELAY_CONFIRMATIONS>
            Number of confirmations a block needs to have before it is submitted [default: 0]

        --bitcoin-relay-start-height <BITCOIN_RELAY_START_HEIGHT>
            Starting height to relay block headers, if not defined use the best height as reported
            by the relay module

        --bitcoin-rpc-pass <BITCOIN_RPC_PASS>
            [env: BITCOIN_RPC_PASS=]

        --bitcoin-rpc-url <BITCOIN_RPC_URL>
            [env: BITCOIN_RPC_URL=]

        --bitcoin-rpc-user <BITCOIN_RPC_USER>
            [env: BITCOIN_RPC_USER=]

        --bitcoin-theft-start-height <BITCOIN_THEFT_START_HEIGHT>
            Starting height for vault theft checks, if not defined automatically start from the
            chain tip

        --btc-confirmations <BTC_CONFIRMATIONS>
            How many bitcoin confirmations to wait for. If not specified, the parachain settings
            will be used (recommended)

        --btc-parachain-connection-timeout-ms <BTC_PARACHAIN_CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --btc-parachain-url <BTC_PARACHAIN_URL>
            Parachain websocket URL [default: ws://127.0.0.1:9944]

        --collateral-currency-id <COLLATERAL_CURRENCY_ID>
            The currency to use for the collateral, e.g. "DOT" or "KSM"

        --collateral-timeout-ms <COLLATERAL_TIMEOUT_MS>
            Timeout in milliseconds to repeat collateralization checks [default: 5000]

        --electrs-url <ELECTRS_URL>
            Url of the electrs server - used for theft reporting. If unset, a default fallback is
            used depending on the network argument

        --keyfile <KEYFILE>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <KEYNAME>
            The name of the account from the keyfile to use

        --keyring <KEYRING>
            Keyring to use, mutually exclusive with keyfile

        --logging-format <LOGGING_FORMAT>
            Logging output format [default: full]

        --max-batch-size <MAX_BATCH_SIZE>
            Max batch size for combined block header submission [default: 16]

        --max-concurrent-requests <MAX_CONCURRENT_REQUESTS>
            Maximum number of concurrent requests

        --max-notifs-per-subscription <MAX_NOTIFS_PER_SUBSCRIPTION>
            Maximum notification capacity for each subscription

        --network <NETWORK>
            Bitcoin network type for address encoding [default: regtest]

        --payment-margin-minutes <PAYMENT_MARGIN_MINUTES>
            Minimum time to the the redeem/replace execution deadline to make the bitcoin payment
            [default: 120]

        --restart-policy <RESTART_POLICY>
            Restart or stop on error [default: always]

        --wrapped-currency-id <WRAPPED_CURRENCY_ID>
            The currency to use for the wrapping, e.g. "INTERBTC" or "KBTC"
```
