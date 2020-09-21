use crate::rpc::{PolkaBtcProvider, SecurityPallet};
use runtime::{PolkaBTC, StatusCode};
use sp_core::H160;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::{Client, ClientBuilder, PairSigner};
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;
use tokio::sync::Mutex;

pub(crate) async fn test_client_with(key: AccountKeyring) -> (Client<PolkaBTC>, TempDir) {
    env_logger::try_init().ok();
    let tmp = TempDir::new("subxt-").expect("failed to create tempdir");
    let config = SubxtClientConfig {
        impl_name: "btc-parachain-full-client",
        impl_version: "0.0.1",
        author: "Interlay Ltd",
        copyright_start_year: 2020,
        db: DatabaseConfig::RocksDb {
            path: tmp.path().join("db"),
            cache_size: 128,
        },
        keystore: KeystoreConfig::Path {
            path: tmp.path().join("keystore"),
            password: None,
        },
        chain_spec: btc_parachain::chain_spec::development_config().unwrap(),
        role: Role::Authority(key),
        telemetry: None,
    };
    let client = ClientBuilder::new()
        .set_client(
            SubxtClient::from_config(config, btc_parachain::service::new_full)
                .expect("Error creating subxt client"),
        )
        .set_page_size(3)
        .build()
        .await
        .expect("Error creating client");
    (client, tmp)
}

#[tokio::test]
async fn test_runtime() {
    let (client, _) = test_client_with(AccountKeyring::Alice).await;

    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let provider = PolkaBtcProvider::new(client, Arc::new(Mutex::new(signer)));

    let status = provider.get_parachain_status().await.unwrap();
    assert_eq!(status, StatusCode::Running);

    provider.register_vault(100, H160::zero()).await.unwrap();
    let vault = provider
        .get_vault(AccountKeyring::Alice.to_account_id())
        .await
        .unwrap();

    assert_eq!(vault.btc_address, H160::zero());
}
