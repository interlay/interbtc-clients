# PolkaBTC Faucet Client

Transfer ROC to users.

## Responsibilities

- Send 1 ROC (testnet DOT) to users and 500 ROC to registered vaults
- Prevent accounts from request more than once every 6 hours

## Getting Started

Run the faucet client:

```
cargo run
```

### Options

When using cargo to run the faucet, arguments to cargo and the faucet are separated by `--`. For example, to pass `--help` to the faucet to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a copy of this output is included below.
```
USAGE:
    cargo run -- [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --http-addr <http-addr>
            Address to listen on for JSON-RPC requests [default: [::0]:3033]

        --keyfile <keyfile>
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>                    The name of the account from the keyfile to use
        --keyring <keyring>                    Keyring to use, mutually exclusive with keyfile
        --polka-btc-url <polka-btc-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --rpc-cors-domain <rpc-cors-domain>    Comma separated list of allowed origins [default: *]
        --user-allowance <user-allowance>
            ROC allowance per request for regular users [default: 1]

        --vault-allowance <vault-allowance>    ROC allowance per request for vaults [default: 500]
```
