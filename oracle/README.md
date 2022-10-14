# Oracle

Automated price feeder for interBTC. Values can be set manually or imported from a supported source.

## Examples

To use a fixed price for BTC/DOT and coingecko for BTC/INTR, use e.g.: 
```shell
cargo run --bin oracle --features parachain-metadata-kintsugi -- --keyring alice --coingecko-url https://api.coingecko.com/api/v3 --oracle-config config.json
```

With the `config.json`:
```json
{
    "currencies": {
        "BTC": {
            "name": "Bitcoin",
            "decimals": 8
        },
        "DOT": {
            "name": "Polkadot",
            "decimals": 10
        },
        "INTR": {
            "name": "Interlay",
            "decimals": 10
        }
    },
    "prices": [
        {
            "pair": [
                "BTC",
                "DOT"
            ],
            "value": 2308
        },
        {
            "pair": [
                "BTC",
                "INTR"
            ],
            "feeds": {
                "coingecko": [
                    [
                        "INTR",
                        "BTC"
                    ]
                ]
            }
        }
    ]
}
```

## Detailed Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the tool to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run --bin oracle --features parachain-metadata-kintsugi -- --help
```

For convenience, a modified version of this output is included below.

```
USAGE:
    oracle [OPTIONS]

OPTIONS:
        --blockcypher-url <BLOCKCYPHER_URL>
            Fetch the bitcoin fee estimate from BlockCypher
            (https://api.blockcypher.com/v1/btc/main)

        --blockstream-url <BLOCKSTREAM_URL>
            Fetch the bitcoin fee estimate from Blockstream (https://blockstream.info/api/)

        --btc-parachain-url <BTC_PARACHAIN_URL>
            Parachain URL, can be over WebSockets or HTTP [default: ws://127.0.0.1:9944]

        --coingecko-api-key <COINGECKO_API_KEY>
            Use a dedicated API key for coingecko pro URL (https://pro-api.coingecko.com/api/v3/)

        --coingecko-url <COINGECKO_URL>
            Fetch the exchange rate from CoinGecko (https://api.coingecko.com/api/v3/)

        --connection-timeout-ms <CONNECTION_TIMEOUT_MS>
            Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]

        --gateio-url <GATEIO_URL>
            Fetch the exchange rate from gate.io

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

        --kraken-url <KRAKEN_URL>
            Fetch the exchange rate from Kraken

        --oracle-config <ORACLE_CONFIG>
            Feed / price config [default: ./oracle-config.json]

    -V, --version
            Print version information
```
