mod api;
mod error;
mod issue;
mod redeem;
mod replace;
mod util;

use bitcoin::BitcoinCore;
use clap::Clap;
use error::Error;
use issue::*;
use log::{error, info};
use redeem::*;
use replace::*;

use runtime::{
    substrate_subxt::PairSigner, PolkaBtcProvider, PolkaBtcRuntime,
};
use sp_keyring::AccountKeyring;
use std::sync::Arc;

/// The Vault client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Keyring for vault.
    #[clap(long, default_value = "bob")]
    keyring: AccountKeyring,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::1]:3030")]
    http_addr: String,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    #[clap(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let btc_rpc = Arc::new(BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;
    let arc_provider = Arc::new(provider.clone());

    let num_confirmations = if opts.dev { 1 } else { 6 };
    let vault_id = opts.keyring.to_account_id();

    // log vault registration result, but keep going upon error, since it might just be
    // that this vault already registered. Note that we can't match this specific error
    // due to inner error type path being private
    match arc_provider
        .register_vault(
            5_000_000_000_000,
            bitcoin::get_hash_from_string("bcrt1qywc4rq6sd778a0zud325xlk5yzmd2w3ed9larg")
                .map_err(|x| -> bitcoin::Error { x.into() })?,
        )
        .await
    {
        Ok(_) => info!("registered vault ok"),
        Err(e) => error!("Failed to register vault {:?} --- {}", e, e.to_string()),
    };

    let issue_listener = listen_for_issue_requests(arc_provider.clone(), vault_id.clone());
    let request_replace_listener =
        listen_for_replace_requests(arc_provider.clone(), vault_id.clone());
    let redeem_listener = listen_for_redeem_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
    );
    let accept_replace_listener = listen_for_accept_replace(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
    );

    let api_listener = api::start(
        arc_provider.clone(),
        opts.http_addr.parse()?,
        opts.rpc_cors_domain,
    );

    let result = tokio::try_join!(
        tokio::spawn(async move {
            api_listener.await;
        }),
        tokio::spawn(async move {
            issue_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            redeem_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            request_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            accept_replace_listener.await.unwrap();
        }),
    );
    match result {
        Ok(res) => {
            println!("{:?}", res);
        }
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    Ok(())
}
