# Testdata Generator

Generate testdata for the BTC Parachain.

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

This tool uses subcommands, e.g. `cargo run -- --keyring bob set-exchange-rate`, and some of these have subcommands of themselves. For example, vault api-calls are made with `cargo run -- api-call vault <API_SUBCOMMAND>`. To get more information on a particular subcommand, use `--help`, e.g. `cargo run -- request-issue --help`.

```
USAGE:
    testdata-gen [OPTIONS] --bitcoin-rpc-url <bitcoin-rpc-url> --bitcoin-rpc-user <bitcoin-rpc-user> --bitcoin-rpc-pass <bitcoin-rpc-pass> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bitcoin-connection-timeout-ms <bitcoin-connection-timeout-ms>
            Timeout in milliseconds to wait for connection to bitcoin-core [default: 60000]

        --bitcoin-rpc-pass <bitcoin-rpc-pass>
            [env: BITCOIN_RPC_PASS=rpcpassword]

        --bitcoin-rpc-url <bitcoin-rpc-url>
            [env: BITCOIN_RPC_URL=http://localhost:18443]

        --bitcoin-rpc-user <bitcoin-rpc-user>
            [env: BITCOIN_RPC_USER=rpcuser]

        --btc-parachain-url <btc-parachain-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --connection-timeout-ms <connection-timeout-ms>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile

        --network <network>
            Bitcoin network type for address encoding [default: regtest]


SUBCOMMANDS:
    accept-replace              Accept replace request of another vault
    execute-redeem              Send BTC to user, must be called by vault
    execute-replace             Accept replace request of another vault
    fund-accounts               Transfer collateral
    get-btc-tx-fees             Get the current estimated bitcoin transaction fees
    get-current-time            Get the time as reported by the chain
    get-exchange-rate           Get the current exchange rate
    help                        Prints this message or the help of the given subcommand(s)
    insert-authorized-oracle    Add a new authorized oracle
    register-vault              Register a new vault using the global keyring
    request-issue               Request issuance  and transfer to vault
    request-redeem              Request that issued tokens be burned to redeem BTC
    request-replace             Request another vault to takeover
    send-bitcoin                Send BTC to an address
    set-btc-tx-fees             Set the current estimated bitcoin transaction fees
    set-exchange-rate           Set the exchange rate
    set-issue-period            Set issue period
    set-redeem-period           Set redeem period
    set-replace-period          Set replace period
```
