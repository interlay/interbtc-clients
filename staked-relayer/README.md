# Staked Relayer

## Responsibilities

- Receive block headers from [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- Submit block headers to the [BTC Parachain](https://github.com/interlay/btc-parachain)
- Monitor the BTC addresses of vaults to report BTC thefts

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

The basic command to run the staked relayer client:

```
source ../.env
cargo run
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the relayer to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a copy of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables.

```
USAGE:
    staked-relayer [OPTIONS] --bitcoin-rpc-url <bitcoin-rpc-url> --bitcoin-rpc-user <bitcoin-rpc-user> --bitcoin-rpc-pass <bitcoin-rpc-pass>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --auto-fund-with-faucet-url <auto-fund-with-faucet-url>
            Automatically fund the staked relayer with collateral received from the faucet and a
            newly generated address. The parameter is the URL of the faucet

        --bitcoin-connection-timeout-ms <bitcoin-connection-timeout-ms>
            Timeout in milliseconds to wait for connection to bitcoin-core [default: 60000]

        --bitcoin-poll-timeout-ms <bitcoin-poll-timeout-ms>
            Timeout in milliseconds to poll Bitcoin [default: 6000]

        --bitcoin-relay-start-height <bitcoin-relay-start-height>
            Starting height to relay block headers, if not defined use the best height as reported
            by the relay module

        --bitcoin-rpc-pass <bitcoin-rpc-pass>
            [env: BITCOIN_RPC_PASS=rpcpassword]

        --bitcoin-rpc-url <bitcoin-rpc-url>
            [env: BITCOIN_RPC_URL=http://localhost:18443]

        --bitcoin-rpc-user <bitcoin-rpc-user>
            [env: BITCOIN_RPC_USER=rpcuser]

        --bitcoin-theft-start-height <bitcoin-theft-start-height>
            Starting height for vault theft checks, if not defined automatically start from the
            chain tip

        --btc-parachain-url <btc-parachain-url>
            Parachain websocket URL [default: ws://127.0.0.1:9944]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile

        --logging-format <logging-format>
            Logging output format [default: full]

        --max-batch-size <max-batch-size>
            Max batch size for combined block header submission [default: 16]

        --max-concurrent-requests <max-concurrent-requests>
            Maximum number of concurrent requests

        --max-notifs-per-subscription <max-notifs-per-subscription>
            Maximum notification capacity for each subscription

        --network <network>
            Bitcoin network type for address encoding [default: regtest]

        --polka-btc-connection-timeout-ms <polka-btc-connection-timeout-ms>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --required-btc-confirmations <required-btc-confirmations>
            Number of confirmations a block needs to have before it is submitted [default: 0]

        --restart-policy <restart-policy>
            Restart or stop on error [default: always]

        --rpc-cors-domain <rpc-cors-domain>
            Comma separated list of allowed origins [default: *]

        --telemetry-url <telemetry-url>                                        Telemetry endpoint
```

## Example

First, ensure you have a running Bitcoin node and a `keyfile.json` as specified above, denoting a Polkadot account. An example keyfile looks as follows:
```
{ 
    "relayer": "car timber smoke zone west involve board success norm inherit door road" 
}
```