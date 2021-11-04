#![cfg(test)]

const DEFAULT_TESTING_CURRENCY: CurrencyId = CurrencyId::DOT;

use super::{
    BtcAddress, BtcPublicKey, BtcRelayPallet, CollateralBalancesPallet, CurrencyId, FixedPointNumber, FixedU128,
    OraclePallet, RawBlockHeader, RelayPallet, ReplacePallet, SecurityPallet, StatusCode, VaultRegistryPallet,
};
use crate::{integration::*, FeedValuesEvent, OracleKey, VaultId, H160, U256};
use module_bitcoin::{formatter::TryFormattable, types::BlockBuilder};
use sp_keyring::AccountKeyring;
use std::{convert::TryInto, time::Duration};

fn dummy_public_key() -> BtcPublicKey {
    BtcPublicKey {
        0: [
            2, 205, 114, 218, 156, 16, 235, 172, 106, 37, 18, 153, 202, 140, 176, 91, 207, 51, 187, 55, 18, 45, 222,
            180, 119, 54, 243, 97, 173, 150, 161, 169, 230,
        ],
    }
}

pub fn to_block_header(value: Vec<u8>) -> RawBlockHeader {
    crate::RawBlockHeader {
        0: value.try_into().unwrap(),
    }
}

async fn set_exchange_rate(client: SubxtClient) {
    let oracle_provider = setup_provider(client, AccountKeyring::Bob).await;
    let key = OracleKey::ExchangeRate(DEFAULT_TESTING_CURRENCY);
    let exchange_rate = FixedU128::saturating_from_rational(1u128, 100u128);
    oracle_provider
        .feed_values(vec![(key, exchange_rate)])
        .await
        .expect("Unable to set exchange rate");
}

#[tokio::test(flavor = "multi_thread")]
#[procedural::with_big_stack]
async fn test_getters() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;

    tokio::join!(
        async {
            assert_eq!(parachain_rpc.get_free_balance(CurrencyId::DOT).await.unwrap(), 1 << 60);
        },
        async {
            assert_eq!(parachain_rpc.get_parachain_status().await.unwrap(), StatusCode::Error);
        },
        async {
            assert!(parachain_rpc.get_replace_dust_amount().await.unwrap() > 0);
        },
        async {
            assert!(parachain_rpc.get_current_active_block_number().await.unwrap() == 0);
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
#[procedural::with_big_stack]
async fn test_is_transaction_invalid() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let vault_id = VaultId::new(AccountKeyring::Alice.into(), CurrencyId::DOT, CurrencyId::INTERBTC);
    let err = parachain_rpc.is_transaction_invalid(&vault_id, &[]).await;

    parachain_rpc
        .get_vaults_by_account_id(&AccountKeyring::Alice.into())
        .await
        .unwrap();
    let key = OracleKey::ExchangeRate(DEFAULT_TESTING_CURRENCY);
    let exchange_rate = FixedU128::saturating_from_rational(1u128, 100u128);
    parachain_rpc
        .feed_values(vec![(key.clone(), exchange_rate)])
        .await
        .unwrap();
    parachain_rpc.feed_values(vec![(key, exchange_rate)]).await.unwrap();
    parachain_rpc.wrapped_to_collateral(2532523).await.unwrap();
    err.unwrap();
}

#[tokio::test]
#[procedural::with_big_stack]
#[ignore]
async fn test_outdated_nonce_matching() {
    env_logger::init();
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let err = parachain_rpc.get_outdated_nonce_error().await;
    log::error!("Error: {:?}", err);
    assert!(err.is_invalid_transaction())
}

#[tokio::test]
#[procedural::with_big_stack]
async fn test_subxt_processing_events_after_dispatch_error() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;

    let oracle_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let invalid_oracle = setup_provider(client, AccountKeyring::Dave).await;

    let event_listener =
        crate::integration::assert_event::<FeedValuesEvent, _>(Duration::from_secs(60), parachain_rpc.clone(), |_| {
            true
        });

    let key = OracleKey::ExchangeRate(DEFAULT_TESTING_CURRENCY);
    let exchange_rate = FixedU128::saturating_from_rational(1u128, 100u128);

    let result = tokio::join!(
        event_listener,
        invalid_oracle.feed_values(vec![(key.clone(), exchange_rate)]),
        oracle_provider.feed_values(vec![(key, exchange_rate)])
    );

    // ensure first set_exchange_rate failed and second succeeded.
    result.1.unwrap_err();
    result.2.unwrap();
}

#[tokio::test]
#[procedural::with_big_stack]
async fn test_register_vault() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;
    set_exchange_rate(client.clone()).await;

    let vault_id = VaultId::new(AccountKeyring::Alice.into(), CurrencyId::DOT, CurrencyId::INTERBTC);

    parachain_rpc
        .register_vault(&vault_id, 100, dummy_public_key())
        .await
        .unwrap();
    let vault = parachain_rpc.get_vault(&vault_id).await.unwrap();
    assert_eq!(vault.wallet.public_key, dummy_public_key());
}

#[tokio::test]
#[procedural::with_big_stack]
async fn test_btc_relay() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;
    set_exchange_rate(client.clone()).await;

    let address = BtcAddress::P2PKH(H160::zero());
    let mut height = 0;

    let block = BlockBuilder::new()
        .with_version(4)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()))
        .unwrap();

    let mut block_hash = block.header.hash;
    let block_header = to_block_header(block.header.try_format().unwrap());

    parachain_rpc.initialize_btc_relay(block_header, height).await.unwrap();

    assert_eq!(parachain_rpc.get_best_block().await.unwrap(), block_hash.into());
    assert_eq!(parachain_rpc.get_best_block_height().await.unwrap(), height);

    for _ in 0..4 {
        height += 1;
        println!("Processing height: {}", height);

        let block = BlockBuilder::new()
            .with_previous_hash(block_hash)
            .with_version(4)
            .with_coinbase(&address, 50, height - 1)
            .with_timestamp(1588813835)
            .mine(U256::from(2).pow(254.into()))
            .unwrap();

        block_hash = block.header.hash;
        let block_header = to_block_header(block.header.try_format().unwrap());

        parachain_rpc.store_block_header(block_header).await.unwrap();

        assert_eq!(parachain_rpc.get_best_block().await.unwrap(), block_hash.into());
        assert_eq!(parachain_rpc.get_best_block_height().await.unwrap(), height);
    }
}
