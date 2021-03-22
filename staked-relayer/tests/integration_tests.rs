#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use runtime::integration::*;

use bitcoin::{BitcoinCoreApi, BlockHash, Hash, TransactionExt, Txid};
use futures::{
    channel::mpsc,
    future::{join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use log::*;
use runtime::{
    pallets::staked_relayers::*,
    substrate_subxt::{Event, PairSigner},
    BtcAddress, ErrorCode, ExchangeRateOraclePallet, FeePallet, FixedPointNumber, FixedU128, H256Le, IssuePallet,
    PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet, ReplacePallet, StakedRelayerPallet, StatusCode, UtilFuncs,
    VaultRegistryPallet,
};
use sp_core::H160;
use sp_keyring::AccountKeyring;
use staked_relayer;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(45);

#[tokio::test(threaded_scheduler)]
async fn test_report_vault_theft_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    root_provider.set_maturity_period(0).await.unwrap();

    relayer_provider.register_staked_relayer(1000000).await.unwrap();

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let vaults = Arc::new(staked_relayer::Vaults::from(Default::default()));

    test_service(
        join(
            staked_relayer::service::report_vault_thefts(
                btc_rpc.clone(),
                relayer_provider.clone(),
                0,
                vaults.clone(),
                Duration::from_secs(1),
            ),
            staked_relayer::service::listen_for_wallet_updates(relayer_provider.clone(), vaults.clone()),
        ),
        async {
            // Theft detection works by extracting the public address from transaction inputs,
            // and comparing them to registered vault addresses.
            // We can't easily create a spending input corresponding to a output address, because
            // the input script does not contain the public key; rather, it contains a hash `x`
            // such that `hash(x)` is equal to the output address.
            // To work around this, we create an arbitrary spending script, and then calculate the
            // corresponding output address. Then, we make the vault register the address and we
            // proceed to spend it.

            // step 1: create a spending transaction from some arbitrary address
            let mut transaction = btc_rpc
                .create_transaction(BtcAddress::P2PKH(H160::from_slice(&[4; 20])), 1500, None)
                .await
                .unwrap();
            // set the hash in the input script
            transaction.transaction.input[0].witness = vec![vec![], vec![5; 20]];

            // extract the public address corresponding to the input script
            let input_address = transaction.transaction.extract_input_addresses::<BtcAddress>()[0];
            // now make the vault register it
            vault_provider.register_address(input_address).await.unwrap();

            // now perform the theft
            btc_rpc.send_transaction(transaction).await.unwrap();

            assert_event::<VaultTheftEvent<PolkaBtcRuntime>, _>(TIMEOUT, vault_provider, |_| true).await;
        },
    )
    .await
}

async fn test_oracle_offline_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;

    root_provider.set_maturity_period(0).await.unwrap();

    relayer_provider.register_staked_relayer(1000000).await.unwrap();

    test_service(
        staked_relayer::service::report_offline_oracle(relayer_provider.clone(), Duration::from_secs(1)),
        async {
            assert_event::<ExecuteStatusUpdateEvent<PolkaBtcRuntime>, _>(TIMEOUT, relayer_provider.clone(), |e| {
                matches!(e.add_error, Some(runtime::ErrorCode::OracleOffline))
            })
            .await;
        },
    )
    .await
}

#[tokio::test(threaded_scheduler)]
async fn test_register_deregister_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    root_provider.set_maturity_period(0).await.unwrap();

    relayer_provider.register_staked_relayer(1000000).await.unwrap();

    assert!(relayer_provider.register_staked_relayer(1000000).await.is_err());

    relayer_provider.deregister_staked_relayer().await.unwrap();

    assert!(relayer_provider.deregister_staked_relayer().await.is_err());

    relayer_provider.register_staked_relayer(1000000).await.unwrap();
}

// ignoring this for now after checking with @Sander, as the test times out
#[ignore]
#[tokio::test(threaded_scheduler)]
async fn test_vote_status_no_data_succeeds() {
    let _ = env_logger::try_init();

    let (ref client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    root_provider.set_maturity_period(0).await.unwrap();
    let register_relayer = |key, amount| async move {
        let provider = setup_provider(client.clone(), key).await;
        provider.register_staked_relayer(amount).await.unwrap();
        provider
    };

    let user_provider = setup_provider(client.clone(), AccountKeyring::Ferdie).await;

    let relayer_1 = register_relayer(AccountKeyring::Bob, 10000000).await;
    let relayer_2 = register_relayer(AccountKeyring::Charlie, 10000000).await;

    let btc_rpc_1 = MockBitcoinCore::new(relayer_1.clone()).await;
    let btc_rpc_2 = MockBitcoinCore::new_uninitialized(relayer_2.clone()).await;

    relayer_1
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    vault_provider
        .register_vault(10000000000000, btc_rpc_1.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    test_service(
        staked_relayer::service::listen_for_blocks_stored(btc_rpc_2.clone(), relayer_2, 1000),
        async {
            // make issue and pay
            let issue = user_provider
                .request_issue(10000, vault_provider.get_account_id().clone(), 10000)
                .await
                .unwrap();
            let metadata = btc_rpc_1
                .send_to_address(issue.vault_btc_address, issue.amount_btc as u64, None, TIMEOUT, 0)
                .await
                .unwrap();
            let update =
                assert_event::<StatusUpdateSuggestedEvent<PolkaBtcRuntime>, _>(TIMEOUT, vault_provider, |_| true).await;

            // ignore returned result; it likely has decoding errors
            let _ = root_provider.evaluate_status_update(update.status_update_id).await;

            // we should not be able to use the block relayed by the faulty relayer
            assert!(user_provider
                .execute_issue(
                    issue.issue_id,
                    metadata.txid.translate(),
                    metadata.proof,
                    metadata.raw_tx,
                )
                .await
                .is_err());
        },
    )
    .await;
}
