# Faucet Client

Transfer collateral (e.g. DOT/KSM) and native fees (e.g. INTR/KINT) to users.

## Responsibilities

- Send 1 DOT (testnet DOT) to users and 500 DOT to registered vaults
- Prevent accounts from requesting more than once every 6 hours

## Getting Started

Run the faucet client:

```
cargo run --bin faucet --features standalone-metadata -- --keyring alice --native-currency-id INTR
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the faucet to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run --bin faucet --features standalone-metadata -- --help
```

For convenience, a copy of this output is included below.

```
USAGE:
    faucet [OPTIONS]

FLAGS:
    -h, --help       Print help information
    -V, --version    Print version information

OPTIONS:
        --btc-parachain-connection-timeout-ms <BTC_PARACHAIN_CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --btc-parachain-url <BTC_PARACHAIN_URL>
            Parachain websocket URL [default: ws://127.0.0.1:9944]

        --http-addr <HTTP_ADDR>
            Address to listen on for JSON-RPC requests [default: [::0]:3033]

        --keyfile <KEYFILE>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <KEYNAME>
            The name of the account from the keyfile to use

        --keyring <KEYRING>
            Keyring to use, mutually exclusive with keyfile

        --max-concurrent-requests <MAX_CONCURRENT_REQUESTS>
            Maximum number of concurrent requests

        --max-notifs-per-subscription <MAX_NOTIFS_PER_SUBSCRIPTION>
            Maximum notification capacity for each subscription

        --rpc-cors-domain <RPC_CORS_DOMAIN>
            Comma separated list of allowed origins [default: *]

        --user-allowance <USER_ALLOWANCE>
            Allowance per request for regular users [default: 1]

        --vault-allowance <VAULT_ALLOWANCE>
            Allowance per request for vaults [default: 500]
```
