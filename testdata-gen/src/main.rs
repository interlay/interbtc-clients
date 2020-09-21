use sp_keyring::AccountKeyring;
use substrate_subxt::{ClientBuilder, PairSigner};
use runtime::rpc::PolkaBtcProvider;
use runtime::PolkaBTC;

const POLKA_BTC_URL: &str = "ws://127.0.0.1:9944";

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ClientBuilder::<PolkaBTC>::new()
        .set_url(POLKA_BTC_URL)
        .build()
        .await?;

    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let provider = PolkaBtcProvider::new(client, Arc::new(Mutex::new(signer)));
    let shared_prov = Arc::new(provider);
    let tx_provider = shared_prov.clone();
}
