# Faucet Client

Transfer collateral (e.g. DOT/KSM) and native fees (e.g. INTR/KINT) to users.

## Responsibilities

- Send 1 DOT (testnet DOT) to users and 500 DOT to registered vaults
- Prevent accounts from requesting more than once every 6 hours

## Getting Started

Run the faucet client:

```
cargo run --bin faucet --features parachain-metadata-kintsugi -- --keyring alice --native-currency-id INTR
```

### Options

When using cargo to run this binary, arguments to cargo and the binary are separated by `--`. For example, to pass `--help` to the faucet to get a list of all command line options that is guaranteed to be up date, run:

```
cargo run --bin faucet --features parachain-metadata-kintsugi -- --help
```

For convenience, a copy of this output is included below.

```
Usage: faucet [OPTIONS]

Options:
      --keyring <KEYRING>
          Keyring to use, mutually exclusive with keyfile
      --keyfile <KEYFILE>
          Path to the json file containing key pairs in a map. Valid content of this file is e.g. `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`
      --keyname <KEYNAME>
          The name of the account from the keyfile to use
      --btc-parachain-url <BTC_PARACHAIN_URL>
          Parachain websocket URL [default: wss://api-dev-kintsugi.interlay.io:443/parachain]
      --btc-parachain-connection-timeout-ms <BTC_PARACHAIN_CONNECTION_TIMEOUT_MS>
          Timeout in milliseconds to wait for connection to btc-parachain [default: 60000]
      --max-concurrent-requests <MAX_CONCURRENT_REQUESTS>
          Maximum number of concurrent requests
      --max-notifs-per-subscription <MAX_NOTIFS_PER_SUBSCRIPTION>
          Maximum notification capacity for each subscription
      --http-addr <HTTP_ADDR>
          Address to listen on for JSON-RPC requests [default: [::0]:3033]
      --rpc-cors-domain <RPC_CORS_DOMAIN>
          Comma separated list of allowed origins [default: *]
      --allowance-config <ALLOWANCE_CONFIG>
          Allowance config [default: ./faucet-allowance-config.json]
  -h, --help
          Print help information
  -V, --version
          Print version information
```
