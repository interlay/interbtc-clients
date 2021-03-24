#![cfg(test)]

use crate::integration::*;

use super::{
    BtcAddress, BtcPublicKey, BtcRelayPallet, DotBalancesPallet, ExchangeRateOraclePallet, FixedPointNumber, FixedU128,
    ReplacePallet, SecurityPallet, StakedRelayerPallet, StatusCode, VaultRegistryPallet, MINIMUM_STAKE,
};
use module_bitcoin::{
    formatter::TryFormattable,
    types::{BlockBuilder, RawBlockHeader},
};
use sp_core::{H160, U256};
use sp_keyring::AccountKeyring;

fn dummy_public_key() -> BtcPublicKey {
    BtcPublicKey([
        2, 205, 114, 218, 156, 16, 235, 172, 106, 37, 18, 153, 202, 140, 176, 91, 207, 51, 187, 55, 18, 45, 222, 180,
        119, 54, 243, 97, 173, 150, 161, 169, 230,
    ])
}

async fn set_exchange_rate(client: SubxtClient) {
    let oracle_provider = setup_provider(client, AccountKeyring::Bob).await;
    oracle_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .expect("Unable to set exchange rate");
}

#[tokio::test]
async fn test_getters() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    set_exchange_rate(client.clone()).await;

    assert_eq!(provider.get_free_dot_balance().await.unwrap(), 1 << 60);
    assert_eq!(provider.get_parachain_status().await.unwrap(), StatusCode::Running);
    assert!(provider.get_replace_dust_amount().await.unwrap() > 0);
}

#[tokio::test]
async fn test_register_vault() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    set_exchange_rate(client.clone()).await;

    provider.register_vault(100, dummy_public_key()).await.unwrap();
    let vault = provider.get_vault(AccountKeyring::Alice.to_account_id()).await.unwrap();
    assert_eq!(vault.wallet.public_key, dummy_public_key());
}

#[tokio::test]
async fn test_btc_relay() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    set_exchange_rate(client.clone()).await;

    // must be authorized to submit blocks
    provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let address = BtcAddress::P2PKH(H160::zero());
    let mut height = 0;

    let block = BlockBuilder::new()
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()))
        .unwrap();

    let mut block_hash = block.header.hash().unwrap();
    let block_header =
        RawBlockHeader::from_bytes(&block.header.try_format().unwrap()).expect("could not serialize block header");

    provider.initialize_btc_relay(block_header, height).await.unwrap();

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
        let block_header =
            RawBlockHeader::from_bytes(&block.header.try_format().unwrap()).expect("could not serialize block header");

        provider.store_block_header(block_header).await.unwrap();

        assert_eq!(provider.get_best_block().await.unwrap(), block_hash);
        assert_eq!(provider.get_best_block_height().await.unwrap(), height);
    }
}
