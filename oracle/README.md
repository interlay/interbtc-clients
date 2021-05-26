# Oracle

Automated price feeder for the BTC Parachain. 

## Examples

```shell
cargo run -- --keyring bob --exchange-rate 385523187 --timeout-ms 36000
```

## Detailed Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the tool to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run -- --help
```

For convenience, a modified version of this output is included below.

```
USAGE:
    oracle [FLAGS] [OPTIONS]

FLAGS:
        --coingecko    Fetch the exchange rate from CoinGecko
    -h, --help         Prints help information
    -V, --version      Prints version information

OPTIONS:
        --btc-parachain-url <btc-parachain-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --connection-timeout-ms <connection-timeout-ms>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --exchange-rate <exchange-rate>
            Exchange rate from Planck to Satoshi. hardcoded to 1 BTC = 3855.23187 DOT at granularity
            of 5 [default: 385523187]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile

        --timeout-ms <timeout-ms>
            Timeout for exchange rate setter, default 25 minutes [default: 1500000]
```
