# Runner

Auto-updater software for interbtc clients (vault, oracle, faucet). The Runner runs and auto-updates clients across multiple networks (Interlay, Kintsugi,
testnets), by reading on-chan release data (`ClientsInfo::CurrentClientsRelease` storage map).

> **IMPORTANT**
> 
> It is CRITICAL that the runner is shut down gracefully, otherwise the spawned client process will keep running. If there are multiple running vault executables for the same [Vault ID(s)](https://docs.interlay.io/#/vault/overview?id=multi-collateral-system), redeem requests will be fulfilled by all vault executables, leading to double-spending the BTC in the vault's wallet! The Vault operator will need to provide its own BTC to cover for the loss, to avoid having its [collateral slashed](https://docs.interlay.io/#/guides/bridge?id=_4-optional-retry-or-reimburse-your-request).
> 
> Supported process signals for graceful termination: `SIGHUP`, `SIGTERM`, `SIGINT`, `SIGQUIT`.


```bash
USAGE:
    runner [OPTIONS] --parachain-ws <PARACHAIN_WS> [CLIENT_ARGS]...

ARGS:
    <CLIENT_ARGS>...    CLI arguments to pass to the client executable

OPTIONS:
        --client-type <CLIENT_TYPE>
            Client to run, one of: vault, oracle, faucet. Default is `vault` [default: vault]

        --download-path <DOWNLOAD_PATH>
            Download path for the client executable [default: .]

    -h, --help
            Print help information

        --parachain-ws <PARACHAIN_WS>
            Parachain websocket URL

    -V, --version
            Print version information
```

## How it works
The runner queries raw parachain storage every `BLOCK_TIME` seconds (see `runner.rs`). It does so using [subxt](https://github.com/paritytech/subxt) dynamic queries with manual SCALE decoding, to avoid maintaining chain metadata for the runner. 

Two assumptions hardcoded into the runner that might change, are:
- The release is found under `ClientsInfo::CurrentClientsRelease`
- The data type of the release is [this struct](https://github.com/interlay/interbtc-clients/blob/ffc1ab995e488fbb11bb779a1f50281d700082e7/runner/src/runner.rs#L82).

When a new release URL is found, the executable is downloaded and spawned as a child process of the runner. The previously running executable is killed using `SIGTERM` and removed from the file system.

The runner needs to be terminated gracefully in order to clean up its child process. Otherwise, multiple running vault executables will double-spend redeem requests from their BTC wallet.

## Build

### Install Rust

```shell
curl https://sh.rustup.rs -sSf | sh
```

### Build the Runner

Clone the Runner code and build the binary:

```shell
git clone git@github.com:interlay/interbtc-clients.git
cd interbtc-clients
cargo build --bin runner
```

### Start the Runner

> The runner starts up a vault client, so the client must not be started separately. At any given time there should only be one vault client running for any given `AccountId`. Having multiple vault clients running and using the same `AccountId` can lead to double payments (e.g. on redeem requests).

Move the runner binary into your `$PATH`.

Pass Vault CLI arguments as positional arguments (preceeded by double dashes: `--`), after passing the command options of the runner executable. Example (on Kintsugi Testnet):

```shell
runner \
    # Runner CLI arguments
    --client-type vault \
    --parachain-ws 'wss://api-dev-kintsugi.interlay.io:443/parachain' \
    --download-path <CUSTOM_BINARY_DOWNLOAD_PATH, example: /opt/testnet/runner/> \
    -- \
    # Vault CLI arguments:
    --bitcoin-rpc-url http://localhost:18332 \
    --bitcoin-rpc-user rpcuser \
    --bitcoin-rpc-pass rpcpassword \
    --keyfile keyfile.json \
    --keyname <INSERT_YOUR_KEYNAME, example: 0x0e5aabe5ff862d66bcba0912bf1b3d4364df0eeec0a8137704e2c16259486a71> \
    --faucet-url 'https://api-dev-kintsugi.interlay.io/faucet' \
    --auto-register=KSM=faucet \
    --btc-parachain-url 'wss://api-dev-kintsugi.interlay.io:443/parachain'
```