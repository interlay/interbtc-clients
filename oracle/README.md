# Oracle

Automated price feeder for interBTC. Values can be set manually or imported from a supported source.

## Examples

```shell
cargo run --bin oracle --features standalone-metadata -- --keyring alice --currency-id DOT --exchange-rate 2308 --interval-ms 1000
```

## Detailed Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the tool to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run --bin oracle --features standalone-metadata -- --help
```

For convenience, a modified version of this output is included below.

```
USAGE:
    oracle [OPTIONS]

FLAGS:
    -h, --help       Print help information
    -V, --version    Print version information

OPTIONS:
        --bitcoin-fee <BITCOIN_FEE>
            Estimated fee rate to include a Bitcoin transaction in the next block (~10 min)
            [default: 1]

        --blockstream <BLOCKSTREAM>
            Fetch the bitcoin fee from Blockstream (https://blockstream.info/api/)

        --btc-parachain-url <BTC_PARACHAIN_URL>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --coingecko <COINGECKO>
            Fetch the exchange rate from CoinGecko (https://api.coingecko.com/api/v3/)

        --connection-timeout-ms <CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --currency-id <CURRENCY_ID>...
            Collateral type for exchange rates, e.g. "DOT" or "KSM"

        --exchange-rate <EXCHANGE_RATE>...
            Exchange rate from the collateral currency to the wrapped currency - i.e. 1 BTC = 2308
            DOT

        --interval-ms <INTERVAL_MS>
            Interval for exchange rate setter, default 25 minutes [default: 1500000]

        --keyfile <KEYFILE>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <KEYNAME>
            The name of the account from the keyfile to use

        --keyring <KEYRING>
            Keyring to use, mutually exclusive with keyfile
```
