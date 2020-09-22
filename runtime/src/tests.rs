use super::{PolkaBtcProvider, PolkaBtcRuntime, SecurityPallet, StatusCode};
use module_bitcoin::{
    formatter::Formattable,
    types::{Address, BlockBuilder, RawBlockHeader},
};
use sp_core::{H160, U256};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::PairSigner;
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;
use tokio::sync::Mutex;

async fn test_client_with(key: AccountKeyring) -> PolkaBtcProvider {
    let tmp = TempDir::new("btc-parachain-").expect("failed to create tempdir");
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
        role: Role::Authority(key.clone()),
        telemetry: None,
    };

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());

    PolkaBtcProvider::new(
        SubxtClient::from_config(config, btc_parachain::service::new_full)
            .expect("Error creating subxt client"),
        Arc::new(Mutex::new(signer)),
    )
    .await
    .expect("Error creating client")
}

#[tokio::test]
async fn test_parachain_status() {
    let provider = test_client_with(AccountKeyring::Alice).await;

    let status = provider.get_parachain_status().await.unwrap();
    assert_eq!(status, StatusCode::Running);
}

#[tokio::test]
async fn test_register_vault() {
    let provider = test_client_with(AccountKeyring::Alice).await;

    provider.register_vault(100, H160::zero()).await.unwrap();
    let vault = provider
        .get_vault(AccountKeyring::Alice.to_account_id())
        .await
        .unwrap();
    assert_eq!(vault.btc_address, H160::zero());
}

#[tokio::test]
async fn test_initialize_btc_relay() {
    let provider = test_client_with(AccountKeyring::Alice).await;

    let address = Address::from(*H160::zero().as_fixed_bytes());

    let init_block = BlockBuilder::new()
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()));

    let init_block_hash = init_block.header.hash();
    let raw_init_block_header = RawBlockHeader::from_bytes(&init_block.header.format())
        .expect("could not serialize block header");

    provider
        .initialize_btc_relay(raw_init_block_header, 1000)
        .await
        .unwrap();

    assert_eq!(provider.get_best_block().await.unwrap(), init_block_hash);
    assert_eq!(provider.get_best_block_height().await.unwrap(), 1000);
}
