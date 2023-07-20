#![cfg(test)]

const DEFAULT_TESTING_CURRENCY: CurrencyId = Token(KSM);

use super::{
    BtcAddress, BtcPublicKey, BtcRelayPallet, CollateralBalancesPallet, CurrencyId, FixedPointNumber, FixedU128,
    OraclePallet, RawBlockHeader, ReplacePallet, SecurityPallet, StatusCode, SudoPallet, Token, TryFromSymbol,
    VaultRegistryPallet, KBTC, KINT, KSM,
};
use crate::{
    integration::*, utils_accountid::AccountId32, AccountId, FeedValuesEvent, OracleKey, RuntimeCurrencyInfo, VaultId,
    H160, U256,
};
use module_bitcoin::{formatter::TryFormat, types::BlockBuilder};
pub use primitives::CurrencyId::ForeignAsset;
use primitives::CurrencyId::LendToken;
use serial_test::serial;
use sp_keyring::AccountKeyring;
use std::{process::Child, time::Duration};

fn dummy_public_key() -> BtcPublicKey {
    BtcPublicKey {
        0: [
            2, 205, 114, 218, 156, 16, 235, 172, 106, 37, 18, 153, 202, 140, 176, 91, 207, 51, 187, 55, 18, 45, 222,
            180, 119, 54, 243, 97, 173, 150, 161, 169, 230,
        ],
    }
}

async fn set_exchange_rate() {
    let oracle_provider = setup_custom_provider(AccountKeyring::Bob).await;
    let key = OracleKey::ExchangeRate(DEFAULT_TESTING_CURRENCY);
    let exchange_rate = FixedU128::saturating_from_rational(1u128, 100u128);
    oracle_provider
        .feed_values(vec![(key, exchange_rate)])
        .await
        .expect("Unable to set exchange rate");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_getters() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;

    tokio::join!(
        async {
            assert_eq!(parachain_rpc.get_free_balance(Token(KINT)).await.unwrap(), 1 << 60);
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
    child.kill().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_invalid_tx_matching() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;

    let bob_keyring = AccountKeyring::Bob;
    let bob_substrate_account = bob_keyring.to_account_id();
    let bob = AccountId32(bob_substrate_account.clone().into());

    let err = parachain_rpc.get_invalid_tx_error(bob.into()).await;
    assert!(err.is_invalid_transaction().is_some());
    child.kill().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_too_low_priority_matching() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;

    let bob_keyring = AccountKeyring::Bob;
    let bob_substrate_account = bob_keyring.to_account_id();
    let bob = AccountId32(bob_substrate_account.clone().into());

    let err = parachain_rpc.get_too_low_priority_error(bob.into()).await;
    assert!(err.is_pool_too_low_priority().is_some());
    child.kill().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_subxt_processing_events_after_dispatch_error() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;

    let oracle_provider = setup_custom_provider(AccountKeyring::Bob).await;
    let invalid_oracle = setup_custom_provider(AccountKeyring::Dave).await;

    let event_listener = assert_event::<FeedValuesEvent, _>(Duration::from_secs(80), parachain_rpc.clone(), |_| true);

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
    child.kill().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_register_vault() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;
    set_exchange_rate().await;
    parachain_rpc
        .set_balances(vec![(
            AccountKeyring::Alice.to_account_id().into(),
            1 << 60,
            0,
            DEFAULT_TESTING_CURRENCY,
        )])
        .await
        .expect("Should endow account");

    let alice_keyring = AccountKeyring::Alice;
    let alice_substrate_account = alice_keyring.to_account_id();
    let alice = AccountId32(alice_substrate_account.clone().into());

    let vault_id = VaultId::new(alice.into(), Token(KSM), Token(KBTC));

    parachain_rpc.register_public_key(dummy_public_key()).await.unwrap();
    parachain_rpc.register_vault(&vault_id, 3 * KSM.one()).await.unwrap();
    parachain_rpc.get_vault(&vault_id).await.unwrap();
    assert_eq!(parachain_rpc.get_public_key().await.unwrap(), Some(dummy_public_key()));
    child.kill().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_btc_relay() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;
    set_exchange_rate().await;

    let address = BtcAddress::P2PKH(H160::zero());
    let mut height = 0;

    let block = BlockBuilder::new()
        .with_version(4)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()))
        .unwrap();

    let mut block_hash = block.header.hash;
    let mut raw_block_header = vec![];
    block.header.try_format(&mut raw_block_header).unwrap();
    let raw_block_header = RawBlockHeader(raw_block_header);

    parachain_rpc
        .initialize_btc_relay(raw_block_header, height)
        .await
        .unwrap();

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
        let mut raw_block_header = vec![];
        block.header.try_format(&mut raw_block_header).unwrap();
        let raw_block_header = RawBlockHeader(raw_block_header);

        parachain_rpc.store_block_header(raw_block_header).await.unwrap();

        assert_eq!(parachain_rpc.get_best_block().await.unwrap(), block_hash.into());
        assert_eq!(parachain_rpc.get_best_block_height().await.unwrap(), height);
    }
    child.kill().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_currency_id_parsing() {
    let mut child: Child = start_chain().await.unwrap();
    let (parachain_rpc, _tmp_dir) = default_root_provider_client(AccountKeyring::Alice).await;
    parachain_rpc.register_dummy_assets().await.unwrap();
    parachain_rpc.store_assets_metadata().await.unwrap();
    parachain_rpc.register_lending_markets().await.unwrap();
    parachain_rpc.store_lend_tokens().await.unwrap();

    // test with different capitalization to make sure the check is not case sensitive

    assert_eq!(CurrencyId::try_from_symbol("KiNt".to_string()).unwrap(), Token(KINT));
    assert_eq!(CurrencyId::try_from_symbol("abc".to_string()).unwrap(), ForeignAsset(1));
    assert_eq!(CurrencyId::try_from_symbol("qabC".to_string()).unwrap(), LendToken(0));
    assert_eq!(CurrencyId::try_from_symbol("qkInt".to_string()).unwrap(), LendToken(1));
    // Even if matching as a qToken fails, the foreign asset should still be found.
    // Matching "QQQ" will recursively call `try_from_symbol` function three more times (including
    // with an empty string), because `Q` matches the lend token prefix each time.
    assert_eq!(CurrencyId::try_from_symbol("qQQ".to_string()).unwrap(), ForeignAsset(3));
    assert_eq!(
        CurrencyId::try_from_symbol("TeSt".to_string()).unwrap(),
        ForeignAsset(2)
    );
    assert_eq!(ForeignAsset(2).decimals().unwrap(), 10);
    child.kill().unwrap();
}
