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
    pub fn new_client(&self) -> Result<Client, Error> {
        Ok(Client::new(
            self.bitcoin_rpc_url.clone(),
            Auth::UserPass(
                self.bitcoin_rpc_user.clone(),
                self.bitcoin_rpc_pass.clone(),
            ),
        )?)
    }
}
