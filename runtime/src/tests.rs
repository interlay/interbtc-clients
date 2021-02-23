use super::{
    BtcAddress, BtcPublicKey, BtcRelayPallet, DotBalancesPallet, PolkaBtcProvider, PolkaBtcRuntime,
    SecurityPallet, StakedRelayerPallet, StatusCode, VaultRegistryPallet, MINIMUM_STAKE,
};
use module_bitcoin::{
    formatter::TryFormattable,
    types::{BlockBuilder, RawBlockHeader},
};
use sp_core::{H160, U256};
use sp_keyring::AccountKeyring;
use substrate_subxt::PairSigner;
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;

fn dummy_public_key() -> BtcPublicKey {
    BtcPublicKey([
        2, 205, 114, 218, 156, 16, 235, 172, 106, 37, 18, 153, 202, 140, 176, 91, 207, 51, 187, 55,
        18, 45, 222, 180, 119, 54, 243, 97, 173, 150, 161, 169, 230,
    ])
}

async fn test_client_with(key: AccountKeyring) -> PolkaBtcProvider {
    let tmp = TempDir::new("btc-parachain-").expect("failed to create tempdir");
    let config = SubxtClientConfig {
        impl_name: "btc-parachain-full-client",
        impl_version: "0.0.1",
        author: "Interlay Ltd",
        copyright_start_year: 2020,
        db: DatabaseConfig::ParityDb {
            path: tmp.path().join("db"),
        },
        keystore: KeystoreConfig::Path {
            path: tmp.path().join("keystore"),
            password: None,
        },
        chain_spec: btc_parachain::chain_spec::development_config(),
        role: Role::Authority(key.clone()),
        telemetry: None,
    };

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());

    PolkaBtcProvider::new(
        SubxtClient::from_config(config, btc_parachain_service::new_full)
            .expect("Error creating subxt client"),
        signer,
    )
    .await
    .expect("Error creating client")
}

#[tokio::test]
async fn test_get_free_dot_balance() {
    let provider = test_client_with(AccountKeyring::Alice).await;

    let balance = provider.get_free_dot_balance().await.unwrap();
    assert_eq!(balance, 1 << 60);
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
    provider
        .register_vault(100, dummy_public_key())
        .await
        .unwrap();
    let vault = provider
        .get_vault(AccountKeyring::Alice.to_account_id())
        .await
        .unwrap();
    assert_eq!(vault.wallet.public_key, dummy_public_key());
}

#[tokio::test]
async fn test_btc_relay() {
    let provider = test_client_with(AccountKeyring::Alice).await;
    // must be authorized to submit blocks
    provider
        .register_staked_relayer(MINIMUM_STAKE)
        .await
        .unwrap();

    let address = BtcAddress::P2PKH(H160::zero());
    let mut height = 0;

    let block = BlockBuilder::new()
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()))
        .unwrap();

    let mut block_hash = block.header.hash().unwrap();
    let block_header = RawBlockHeader::from_bytes(&block.header.try_format().unwrap())
        .expect("could not serialize block header");

    provider
        .initialize_btc_relay(block_header, height)
        .await
        .unwrap();

    assert_eq!(provider.get_best_block().await.unwrap(), block_hash);
    assert_eq!(provider.get_best_block_height().await.unwrap(), height);

    for _ in 0..4 {
        height += 1;
        println!("Processing height: {}", height);

        let block = BlockBuilder::new()
            .with_previous_hash(block_hash)
            .with_version(2)
            .with_coinbase(&address, 50, height - 1)
            .with_timestamp(1588813835)
            .mine(U256::from(2).pow(254.into()))
            .unwrap();

        block_hash = block.header.hash().unwrap();
        let block_header = RawBlockHeader::from_bytes(&block.header.try_format().unwrap())
            .expect("could not serialize block header");

        provider.store_block_header(block_header).await.unwrap();

        assert_eq!(provider.get_best_block().await.unwrap(), block_hash);
        assert_eq!(provider.get_best_block_height().await.unwrap(), height);
    }
}
