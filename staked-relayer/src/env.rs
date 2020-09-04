use crate::client::Client as PolkadotClient;
use crate::Error;
use relayer_core::bitcoin::Client as BtcClient;
use std::env::var;

const DEFAULT_CONFIRMATIONS: usize = 1;

pub fn read_env(s: &str) -> Result<String, Error> {
    var(s).map_err(|e| Error::ReadVar(s.to_string(), e))
}

pub fn bitcoin_from_env() -> Result<BtcClient, Error> {
    let url = read_env("BITCOIN_RPC_URL")?;
    let user = read_env("BITCOIN_RPC_USER")?;
    let pass = read_env("BITCOIN_RPC_PASS")?;
    BtcClient::new::<Error>(url, user, pass).map_err(|_| Error::BitcoinClient)
}
