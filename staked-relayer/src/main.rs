use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::{ClientBuilder, PairSigner};

mod http;
mod rpc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // env_logger::init();

    let client = ClientBuilder::<PolkaBTC>::new().build().await?;
    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let provider = rpc::Provider::new(client, Arc::new(signer));

    http::start(provider).await;

    // let listen = node.on_proposal();

    // // node.register_staked_relayer(100).await?;
    // node.suggest_status_update(100, StatusCode::Shutdown)
    //     .join(listen)
    //     .await;

    // node.deregister_staked_relayer().await?;
    // println!("{:?}", result);
    Ok(())
}
