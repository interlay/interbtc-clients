# Runner

Auto-updater software for the vault client. On crash or termination, it restarts the vault to remove the need for running as systemd.


```bash
USAGE:
    runner --chain-rpc <CHAIN_RPC> --vault-config-file <VAULT_CONFIG_FILE>

OPTIONS:
        --chain-rpc <CHAIN_RPC>                    
    -h, --help                                     Print help information
    -V, --version                                  Print version information
        --vault-config-file <VAULT_CONFIG_FILE>    
```

## Run
Create a vault config file, with the same structure as the command-line arguments passed to the vault client binary.
Avoid all quotation marks, as these may cause parsing issues.

Example:
```bash
--bitcoin-rpc-url http://localhost:18443 \
--bitcoin-rpc-user rpcuser \
--bitcoin-rpc-pass rpcpassword \
--keyfile keyfile.json \
--keyname 0x124809d7f1c144393dca887c1e00ce5f833db196dbf5eba66ccd12fed1723144 \
--faucet-url http://localhost:3033 \ 
--auto-register=KSM=faucet \
--btc-parachain-url ws://localhost:9944
```

Pass the path to the file to the runner, along with the websocket URL of the parachain (the same value as that 
of the `btc-parachain-url` flag). Example:
```bash
./runner --chain-rpc 'ws://localhost:9944'   --vault-config-file args.txt
```

## Test
To manually test with the example configuration above, run a local Bitcoin Regtest network and dev mode Interbtc Parachain.

Bitcoin Regtest:
```bash
bitcoind -regtest
```

Interbtc Parachain (WIP on Dan's fork):
```bash
git clone -b feature/vault-release-version https://github.com/savudani8/interbtc
cd interbtc
cargo run --bin interbtc-standalone -- --dev
```

Go to the [apps](https://polkadot.js.org/apps/) explorer on the local node and use sudo to send a `VaultRegistry::setClientRelease` extrinsic with version `1.14.0` and a random 32 byte value for the checksum (not used yet), e.g. `0x122132098310183201928012823109812098210198201298012980981098211`.

Run the runner:
```bash
./runner --chain-rpc 'ws://localhost:9944' --vault-config-file args.txt
```