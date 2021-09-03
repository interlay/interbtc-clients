# Oracle

Automated price feeder for interBTC. Values can be set manually or imported from a supported source.

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
    oracle [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bitcoin-fee <bitcoin-fee>
            Estimated fee rate to include a Bitcoin transaction in the next block (~10 min)
            [default: 1]

        --blockstream <blockstream>
            Fetch the bitcoin fee from Blockstream (https://blockstream.info/api/)

        --btc-parachain-url <btc-parachain-url>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --coingecko <coingecko>
            Fetch the exchange rate from CoinGecko (https://api.coingecko.com/api/v3/)

        --connection-timeout-ms <connection-timeout-ms>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --currency-id <currency-id>
            Collateral type for exchange rates, e.g. "DOT" or "KSM"

        --exchange-rate <exchange-rate>
            Exchange rate from the collateral currency to the wrapped currency - i.e. 1 BTC = 2308
            DOT [default: 2308]

        --interval-ms <interval-ms>
            Interval for exchange rate setter, default 25 minutes [default: 1500000]

        --keyfile <keyfile>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <keyname>
            The name of the account from the keyfile to use

        --keyring <keyring>
            Keyring to use, mutually exclusive with keyfile
```
