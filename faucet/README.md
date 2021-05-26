# Faucet Client

Transfer collateral (e.g. DOT/KSM) to users.

## Responsibilities

- Send 1 DOT (testnet DOT) to users and 500 DOT to registered vaults
- Prevent accounts from requesting more than once every 6 hours

## Getting Started

Run the faucet client:

```
cargo run
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the faucet to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a copy of this output is included below.
```
USAGE:
    faucet [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --btc-parachain-url <btc-parachain-url>
            Parachain websocket URL [default: ws://127.0.0.1:9944]

        --http-addr <http-addr>
            Address to listen on for JSON-RPC requests [default: [::0]:3033]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile

        --max-concurrent-requests <max-concurrent-requests>
            Maximum number of concurrent requests

        --max-notifs-per-subscription <max-notifs-per-subscription>
            Maximum notification capacity for each subscription

        --polka-btc-connection-timeout-ms <polka-btc-connection-timeout-ms>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --rpc-cors-domain <rpc-cors-domain>
            Comma separated list of allowed origins [default: *]

        --user-allowance <user-allowance>
            Allowance per request for regular users [default: 1]

        --vault-allowance <vault-allowance>
            Allowance per request for vaults [default: 500]
```
