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
- Replace
  - Request Replace
  - Execute Replace

- Receive block headers from [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- Submit block headers to the [BTC Parachain](https://github.com/interlay/interbtc)

## Prerequisites

Download and start [Bitcoin Core](https://bitcoin.org/en/bitcoin-core/):

```
bitcoind -regtest -server
```

Build and run the [interBTC Parachain](https://github.com/interlay/interbtc):

```
git clone git@gitlab.com:interlay/interbtc.git
cargo run --bin interbtc-parachain -- --dev --tmp
```

## Getting Started

The basic command to run the vault client:

```
source ../.env
cargo run --bin vault --features parachain-metadata-kintsugi
```

### Examples

```shell
# bitcoin private key (for light client)
vault generate-bitcoin-key private-key.wif --network bitcoin

# parachain sr25519 key
vault generate-parachain-key keyfile.json

# start the vault client
vault \
    --bitcoin-rpc-url http://localhost:18332 \
    --bitcoin-rpc-user rpcuser \
    --bitcoin-rpc-pass rpcpassword \
    --keyfile keyfile.json \
    --keyname $(cat keyfile.json | jq -r 'keys[0]')
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the vault to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run --bin vault --features parachain-metadata-kintsugi -- --help
```

For convenience, a copy of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables. 

```
USAGE:
    vault [OPTIONS]
    vault <SUBCOMMAND>

OPTIONS:
        --auto-rbf
            Bump bitcoin tx fees whenever the oracle reports a new, higher inclusion fee estimate

        --auto-register <AUTO_REGISTER>
            Automatically register the vault with the given amount of collateral and a newly
            generated address

        --bitcoin-connection-timeout-ms <BITCOIN_CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to bitcoin-core
            
            [default: 60000]

        --bitcoin-poll-interval-ms <BITCOIN_POLL_INTERVAL_MS>
            Timeout in milliseconds to poll Bitcoin
            
            [default: 6000]

        --bitcoin-relay-confirmations <BITCOIN_RELAY_CONFIRMATIONS>
            Number of confirmations a block needs to have before it is submitted
            
            [default: 0]

        --bitcoin-relay-start-height <BITCOIN_RELAY_START_HEIGHT>
            Starting height to relay block headers, if not defined use the best height as reported
            by the relay module

        --bitcoin-rpc-pass <BITCOIN_RPC_PASS>
            [env: BITCOIN_RPC_PASS=]

        --bitcoin-rpc-url <BITCOIN_RPC_URL>
            [env: BITCOIN_RPC_URL=]

        --bitcoin-rpc-user <BITCOIN_RPC_USER>
            [env: BITCOIN_RPC_USER=]

        --bitcoin-wif <BITCOIN_WIF>
            File containing the WIF encoded Bitcoin private key

        --btc-confirmations <BTC_CONFIRMATIONS>
            How many bitcoin confirmations to wait for. If not specified, the parachain settings
            will be used (recommended)

        --btc-parachain-connection-timeout-ms <BTC_PARACHAIN_CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to btc-parachain
            
            [default: 60000]

        --btc-parachain-url <BTC_PARACHAIN_URL>
            Parachain websocket URL
            
            [default: wss://api-dev-kintsugi.interlay.io:443/parachain]

        --collateral-timeout-ms <COLLATERAL_TIMEOUT_MS>
            Timeout in milliseconds to repeat collateralization checks
            
            [default: 5000]

        --electrs-url <ELECTRS_URL>
            Url of the electrs server. If unset, a default fallback is used depending on the
            detected network

        --faucet-url <FAUCET_URL>
            Pass the faucet URL for auto-registration

    -h, --help
            Print help information

        --keyfile <KEYFILE>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <KEYNAME>
            The name of the account from the keyfile to use

        --keyring <KEYRING>
            Keyring to use, mutually exclusive with keyfile

        --light
            Experimental: Run in light client mode

        --logging-format <LOGGING_FORMAT>
            Logging output format
            
            [default: full]

        --max-batch-size <MAX_BATCH_SIZE>
            Max batch size for combined block header submission
            
            [default: 16]

        --max-concurrent-requests <MAX_CONCURRENT_REQUESTS>
            Maximum number of concurrent requests

        --max-notifs-per-subscription <MAX_NOTIFS_PER_SUBSCRIPTION>
            Maximum notification capacity for each subscription

        --no-api
            Don't run the RPC API

        --no-auto-refund
            Deprecated - kept only to not break clients

        --no-auto-replace
            Opt out of participation in replace requests

        --no-bitcoin-block-relay
            Don't relay bitcoin block headers

        --no-issue-execution
            Don't try to execute issues

        --no-prometheus
            Do not expose a Prometheus metric endpoint

        --no-random-delay
            Attempt to execute best-effort transactions immediately, rather than using a random
            delay

        --payment-margin-minutes <PAYMENT_MARGIN_MINUTES>
            Minimum time to the the redeem/replace execution deadline to make the bitcoin payment
            
            [default: 120]

        --prometheus-external
            Expose Prometheus exporter on all interfaces.
            
            Default is local.

        --prometheus-port <PROMETHEUS_PORT>
            Specify Prometheus exporter TCP Port
            
            [default: 9615]

        --restart-policy <RESTART_POLICY>
            Restart or stop on error
            
            [default: always]

    -V, --version
            Print version information

SUBCOMMANDS:
    generate-bitcoin-key
            Generate the WIF encoded Bitcoin private key
    generate-parachain-key
            Generate the sr25519 parachain key pair
    help
            Print this message or the help of the given subcommand(s)
    run
            Run the Vault client (default)
```
