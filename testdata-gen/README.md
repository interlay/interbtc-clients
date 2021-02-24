# PolkaBTC Testdata

Generate testdata for the BTC-Parachain.

## Examples

```shell
source ../.env
cargo run -- --keyring bob set-exchange-rate --exchange-rate 1
cargo run -- --keyring bob api-call vault request-replace --amount 1000 --griefing-collateral 1000
```

## Detailed Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the tool to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a modified version of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables.

This tool uses subcommands, e.g. `cargo run -- --keyring bob set-exchange-rate`, and some of these have subcommands of themselves. For example, vault api-calls are made with `cargo run -- api-call vault <API_SUBCOMMAND>`. To get more info about sub commands, use `--help`, e.g. `cargo run -- request-issue --help` or `cargo run -- api-call vault register-vault --help`.

```
USAGE:
    testdata-gen [OPTIONS] --bitcoin-rpc-url <bitcoin-rpc-url> --bitcoin-rpc-user <bitcoin-rpc-user> --bitcoin-rpc-pass <bitcoin-rpc-pass> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bitcoin-rpc-pass <bitcoin-rpc-pass>    [env: BITCOIN_RPC_PASS=rpcpassword]
        --bitcoin-rpc-url <bitcoin-rpc-url>      [env: BITCOIN_RPC_URL=http://localhost:18443]
        --bitcoin-rpc-user <bitcoin-rpc-user>    [env: BITCOIN_RPC_USER=rpcuser]
        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>                      The name of the account from the keyfile to use
        --keyring <keyring>                      Keyring to use, mutually exclusive with keyfile
        --polka-btc-url <polka-btc-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]


SUBCOMMANDS:
    accept-replace                 Accept replace request of another vault
    api-call                       Send a API request
    execute-redeem                 Send BTC to user, must be called by vault
    execute-replace                Accept replace request of another vault
    fund-accounts                  Transfer DOT collateral
    get-btc-tx-fees                Get the current estimated bitcoin transaction fees
    get-current-time               Get the time as reported by the chain
    get-exchange-rate              Get the current DOT to BTC exchange rate
    help                           Prints this message or the help of the given subcommand(s)
    register-vault                 Register a new vault using the global keyring
    request-issue                  Request issuance of PolkaBTC and transfer to vault
    request-redeem                 Request that PolkaBTC be burned to redeem BTC
    request-replace                Request another vault to takeover
    send-bitcoin                   Send BTC to an address
    set-btc-tx-fees                Set the current estimated bitcoin transaction fees
    set-exchange-rate              Set the DOT to BTC exchange rate
    set-issue-period               Set issue period
    set-redeem-period              Set redeem period
    set-relayer-maturity-period    Set relayer maturity period
    set-replace-period             Set replace period
```
