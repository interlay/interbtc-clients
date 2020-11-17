use crate::Error;
use bitcoincore_rpc::{Auth, Client};
use clap::Clap;

#[derive(Clap)]
pub struct BitcoinOpts {
    #[clap(long, env = "BITCOIN_RPC_URL")]
    bitcoin_rpc_url: String,

    #[clap(long, env = "BITCOIN_RPC_USER")]
    bitcoin_rpc_user: String,

    #[clap(long, env = "BITCOIN_RPC_PASS")]
    bitcoin_rpc_pass: String,
}

impl BitcoinOpts {
    pub fn new_client(&self, wallet: Option<&str>) -> Result<Client, Error> {
        let url = match wallet {
            Some(x) => format!("{}/wallet/{}", self.bitcoin_rpc_url.clone(), x),
            None => self.bitcoin_rpc_url.clone(),
        };
        Ok(Client::new(
            url,
            Auth::UserPass(self.bitcoin_rpc_user.clone(), self.bitcoin_rpc_pass.clone()),
        )?)
    }
}
