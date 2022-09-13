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

## Run
Pass the CLI client arguments as positional arguments (preceeded by double dashes: `--`), after passing the command options of the `runner` executable. Example:
```bash
./runner --client-type vault --parachain-ws 'ws://localhost:9944' --download-path=./runner_tmp_dir -- --bitcoin-rpc-url 'http://localhost:18443' --bitcoin-rpc-user rpcuser --bitcoin-rpc-pass rpcpassword --keyfile keyfile.json --keyname 0xa81f76187f1e5d2059f67439c4242a92a5cd66a409579db73f156c6e2aae5102 --faucet-url 'http://localhost:3033' --auto-register=KSM=faucet --btc-parachain-url 'ws://localhost:9944'
```

## How it works
The runner queries raw parachain storage every `BLOCK_TIME` seconds (see `runner.rs`). It does so using [subxt](https://github.com/paritytech/subxt) dynamic queries with manual SCALE decoding, to avoid maintaining chain metadata for the runner. 

Two assumptions hardcoded into the runner that might change, are:
- The release is found under `ClientsInfo::CurrentClientsRelease`
- The data type of the release is [this struct](https://github.com/interlay/interbtc-clients/blob/b74d1c0c1426f0b481cf90b9a783df69fe54a614/runner/src/runner.rs#L73).

When a new release URL is found, the executable is downloaded and spawned as a child process of the runner. The previously running executable is killed using `SIGTERM` and removed from the file system.

The runner needs to be terminated gracefully in order to clean up its child process. Otherwise, multiple running vault executables will double-spend redeem requests from their BTC wallet.
