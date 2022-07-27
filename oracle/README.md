# Oracle

Automated price feeder for interBTC. Values can be set manually or imported from a supported source.

## Examples

To use a fixed price for DOT and the coingecko for INTR, use e.g.: 
```shell
cargo run --bin oracle --features standalone-metadata -- --keyring alice --currency-id DOT=2308 --currency-id INTR
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

        --coingecko-api-key <COINGECKO_API_KEY>
            Use a dedicated API key for coingecko pro URL (https://pro-api.coingecko.com/api/v3/)

        --connection-timeout-ms <CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --currency-id <CURRENCY_ID>
            Collateral type for exchange rates, e.g. "DOT" or "KSM". The exchange rate will be
            fetched from coingecko unless explicitly set as e.g. "KSM=123", in which case the given
            exchange rate will be used. The rate will be in while units e.g. KSM/BTC

    -h, --help
            Print help information

        --interval-ms <INTERVAL_MS>
            Interval for exchange rate setter, default 25 minutes [default: 1500000]

        --keyfile <KEYFILE>
            Path to the json file containing key pairs in a map. Valid content of this file is e.g.
            `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`

        --keyname <KEYNAME>
            The name of the account from the keyfile to use

        --keyring <KEYRING>
            Keyring to use, mutually exclusive with keyfile

    -V, --version
            Print version information
```
