# PolkaBTC Vault

## Responsibilities

- Register
  - Lock DOT collateral in Vault Registry
  - Submit current BTC address to Vault Registry
- Redeem
  - Listen for redeem events
  - Send BTC transaction to user
  - Get BTC transaction inclusion proof and raw tx
  - Execute redeem with corresponding redeem id, tx inclusion proof and raw tx
- Collateral balance
  - Observe collateralization rate in Vault Registry
  - Withdraw/lock collateral to keep rate consistent
- Replace
  - Request Replace
  - Execute Replace

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

The basic command to run the vault client:

```
source ../.env
cargo run
```

### Options

When using cargo to run the vault, arguments to cargo and the vault are separated by `--`. For example, to pass `--help` to the vault to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a copy of this output is included below. Note that the bitcoin RPC configuration can be passed either as command line arguments, or as environment variables. By running `source ../.env`, the default RPC configuration is loaded into environment variables. 

```
USAGE:
    cargo run -- [FLAGS] [OPTIONS] --bitcoin-rpc-url <bitcoin-rpc-url> --bitcoin-rpc-user <bitcoin-rpc-user> --bitcoin-rpc-pass <bitcoin-rpc-pass>

FLAGS:
    -h, --help                              Prints help information
        --no-api                            Don't run the RPC API
        --no-auto-auction                   Opt out of auctioning under-collateralized vaults
        --no-auto-replace                   Opt out of participation in replace requests
        --no-issue-execution                Don't try to execute issues
        --no-startup-collateral-increase    Don't check the collateralization rate at startup
    -V, --version                           Prints version information

OPTIONS:
        --auto-register-with-collateral <auto-register-with-collateral>
            Automatically register the vault with the given amount of collateral and a newly
            generated address

        --auto-register-with-faucet-url <auto-register-with-faucet-url>
            Automatically register the vault with the collateral received from the faucet and a newly
            generated address. The parameter is the URL of the faucet

        --bitcoin-rpc-pass <bitcoin-rpc-pass>                              [env: BITCOIN_RPC_PASS=]
        --bitcoin-rpc-url <bitcoin-rpc-url>                                [env: BITCOIN_RPC_URL=]
        --bitcoin-rpc-user <bitcoin-rpc-user>                              [env: BITCOIN_RPC_USER=]
        --btc-confirmations <btc-confirmations>
            How many bitcoin confirmations to wait for. If not specified, the parachain settings
            will be used (recommended)

        --collateral-timeout-ms <collateral-timeout-ms>
            Timeout in milliseconds to repeat collateralization checks [default: 5000]

        --http-addr <http-addr>
            Address to listen on for JSON-RPC requests [default: [::0]:3031]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile

        --max-collateral <max-collateral>
            Maximum total collateral to keep the vault securely collateralized [default: 1000000]

        --network <network>
            Bitcoin network type for address encoding [default: regtest]

        --polka-btc-url <polka-btc-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --rpc-cors-domain <rpc-cors-domain>
            Comma separated list of allowed origins [default: *]
```

## Example

First, ensure you have a running Bitcoin node and a `keyfile.json` as specified above. An example keyfile looks as follows:
```
{ 
    "vault": "car timber smoke zone west involve board success norm inherit door road" 
}
```

Next, ensure the Polkadot account whose mnemonic you provided in `keyfile.json` is funded with enough DOT to pay for the registration transaction.

Then, run the vault and register it with the parachain as in the example below:
```
cargo run -- \
    --bitcoin-rpc-url http://localhost:18332 \
    --bitcoin-rpc-user rpcuser \
    --bitcoin-rpc-pass rpcpass \
    --keyfile /path/to/keyfile.json \
    --keyname vault \
    --polka-btc-url 'wss://beta.polkabtc.io/api/parachain'
```

Once the vault is running, go to https://beta.polkabtc.io to the Vault page and register some collateral, so the vault you registered can start issuing. You can also check its status on the Dashboard page.
