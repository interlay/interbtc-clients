# Runner

Auto-updater software for the vault client. The Runner runs and auto-updates Vault clients across multiple networks (Interlay, Kintsugi,
testnets).


```bash
USAGE:
    runner [OPTIONS] --chain-rpc <CHAIN_RPC> [VAULT_ARGS]...

ARGS:
    <VAULT_ARGS>...    

OPTIONS:
        --chain-rpc <CHAIN_RPC>            
        --download-path <DOWNLOAD_PATH>    [default: .]
    -h, --help                             Print help information
    -V, --version                          Print version information  
```

## Run
Pass the CLI vault arguments as positional arguments, after passing the command options of the `runner` executable. Example:
```bash
./runner --chain-rpc 'ws://localhost:9944' --download-path=./runner_tmp_dir -- --bitcoin-rpc-url 'http://localhost:18443' --bitcoin-rpc-user rpcuser --bitcoin-rpc-pass rpcpassword --keyfile keyfile.json --keyname 0xa81f76187f1e5d2059f67439c4242a92a5cd66a409579db73f156c6e2aae5102 --faucet-url 'http://localhost:3033' --auto-register=KSM=faucet --btc-parachain-url 'ws://localhost:9944'
```
