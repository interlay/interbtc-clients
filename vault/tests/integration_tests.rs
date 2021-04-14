#![cfg(feature = "integration")]

use bitcoin::BitcoinCoreApi;
use futures::{
    channel::mpsc,
    future::{join, join3, join4, try_join},
    FutureExt, SinkExt,
};
use runtime::{
    integration::*,
    pallets::{issue::*, redeem::*, refund::*, replace::*, treasury::*, vault_registry::*},
    BtcAddress, ExchangeRateOraclePallet, FixedPointNumber, FixedU128, IssuePallet, PolkaBtcHeader, PolkaBtcProvider,
    PolkaBtcRuntime, RedeemPallet, ReplacePallet, StakedRelayerPallet, UtilFuncs, VaultRegistryPallet, MINIMUM_STAKE,
};
use sp_core::{H160, H256};
use sp_keyring::AccountKeyring;
use std::{sync::Arc, time::Duration};
use vault::{self, IssueRequests, RequestEvent};

const TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test(threaded_scheduler)]
async fn test_redeem_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(&user_provider, &btc_rpc, vault_provider.get_account_id(), issue_amount).await;

    test_service(
        vault::service::listen_for_redeem_requests(vault_provider.clone(), btc_rpc, 0),
        async {
            let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
            let vault_id = vault_provider.clone().get_account_id().clone();
            let redeem_id = user_provider.request_redeem(10000, address, vault_id).await.unwrap();
            assert_redeem_event(TIMEOUT, user_provider, redeem_id).await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_replace_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    new_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    let (replace_event_tx, _) = mpsc::channel::<RequestEvent>(16);
    test_service(
        join(
            vault::service::listen_for_replace_requests(
                new_vault_provider.clone(),
                btc_rpc.clone(),
                replace_event_tx.clone(),
                true,
            ),
            vault::service::listen_for_accept_replace(old_vault_provider.clone(), btc_rpc.clone(), 0),
        ),
        async {
            let replace_id = old_vault_provider.request_replace(issue_amount, 1000000).await.unwrap();

            assert_event::<AcceptReplaceEvent<PolkaBtcRuntime>, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                e.replace_id == replace_id
            })
            .await;
            assert_event::<ExecuteReplaceEvent<PolkaBtcRuntime>, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                e.replace_id == replace_id
            })
            .await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_maintain_collateral_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(&user_provider, &btc_rpc, vault_provider.get_account_id(), issue_amount).await;

    test_service(
        vault::service::maintain_collateralization_rate(vault_provider.clone(), 1000000000),
        async {
            // dot per btc increases by 10%
            relayer_provider
                .set_exchange_rate_info(FixedU128::saturating_from_rational(110u128, 10000u128))
                .await
                .unwrap();
            assert_event::<LockAdditionalCollateralEvent<PolkaBtcRuntime>, _>(TIMEOUT, vault_provider.clone(), |e| {
                assert_eq!(e.new_collateral, vault_collateral / 10);
                true
            })
            .await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_withdraw_replace_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    new_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    let (replace_id, event) = join(
        old_vault_provider
            .request_replace(issue_amount, 1000000)
            .map(Result::unwrap),
        assert_event::<RequestReplaceEvent<PolkaBtcRuntime>, _>(TIMEOUT, old_vault_provider.clone(), |_| true),
    )
    .await;
    assert_eq!(replace_id, event.replace_id);

    join(
        old_vault_provider.withdraw_replace(replace_id).map(Result::unwrap),
        assert_event::<WithdrawReplaceEvent<PolkaBtcRuntime>, _>(TIMEOUT, old_vault_provider.clone(), |e| {
            e.replace_id == replace_id
        }),
    )
    .await;

    let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
    assert!(new_vault_provider
        .accept_replace(replace_id, vault_collateral, address)
        .await
        .is_err());
}

#[tokio::test(threaded_scheduler)]
async fn test_cancellation_succeeds() {
    // tests cancellation of issue, redeem and replace.
    // issue and replace cancellation is tested through the vault's cancellation service.
    // cancel_redeem is called manually
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount * 10).await;
    old_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    new_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    // set low timeout periods
    root_provider.set_issue_period(1).await.unwrap();
    root_provider.set_replace_period(1).await.unwrap();
    root_provider.set_redeem_period(1).await.unwrap();

    let (issue_block_tx, issue_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);
    let (replace_event_tx, replace_event_rx) = mpsc::channel::<RequestEvent>(16);

    let (replace_block_tx, replace_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);
    let (issue_event_tx, issue_event_rx) = mpsc::channel::<RequestEvent>(16);

    let block_listener = new_vault_provider.clone();
    let issue_set = Arc::new(IssueRequests::new());

    let issue_request_listener = vault::service::listen_for_issue_requests(
        new_vault_provider.clone(),
        btc_rpc.clone(),
        issue_event_tx.clone(),
        issue_set.clone(),
    );

    let mut issue_cancellation_scheduler = vault::service::CancellationScheduler::new(
        new_vault_provider.clone(),
        new_vault_provider.get_account_id().clone(),
    );
    let mut replace_cancellation_scheduler = vault::service::CancellationScheduler::new(
        new_vault_provider.clone(),
        new_vault_provider.get_account_id().clone(),
    );
    let issue_canceller = issue_cancellation_scheduler
        .handle_cancellation::<vault::service::IssueCanceller>(issue_block_rx, issue_event_rx);
    let replace_canceller = replace_cancellation_scheduler
        .handle_cancellation::<vault::service::ReplaceCanceller>(replace_block_rx, replace_event_rx);

    let block_listener = async move {
        let issue_block_tx = &issue_block_tx;
        let replace_block_tx = &replace_block_tx;

        block_listener
            .clone()
            .on_block(move |header| async move {
                issue_block_tx.clone().send(header.clone()).await.unwrap();
                replace_block_tx.clone().send(header.clone()).await.unwrap();
                Ok(())
            })
            .await
            .unwrap();
    };

    test_service(
        join4(
            issue_canceller.map(Result::unwrap),
            replace_canceller.map(Result::unwrap),
            issue_request_listener.map(Result::unwrap),
            block_listener,
        ),
        async {
            let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));

            // setup the to-be-cancelled redeem
            let redeem_id = user_provider
                .request_redeem(20000, address, old_vault_provider.get_account_id().clone())
                .await
                .unwrap();

            let ((replace_id, issue_id), cancel_issue_event, cancel_replace_event) = join3(
                async {
                    // setup the to-be-cancelled replace
                    let replace_id = old_vault_provider
                        .request_replace(issue_amount / 2, 1000000)
                        .await
                        .unwrap();
                    new_vault_provider
                        .accept_replace(replace_id, 10000000, address)
                        .await
                        .unwrap();
                    replace_event_tx.clone().send(RequestEvent::Opened).await.unwrap();

                    // setup the to-be-cancelled issue
                    let issue = user_provider
                        .request_issue(issue_amount, new_vault_provider.get_account_id().clone(), 10000)
                        .await
                        .unwrap();
                    (replace_id, issue.issue_id)
                },
                assert_event::<CancelIssueEvent<PolkaBtcRuntime>, _>(
                    Duration::from_secs(60),
                    user_provider.clone(),
                    |_| true,
                ),
                assert_event::<CancelReplaceEvent<PolkaBtcRuntime>, _>(
                    Duration::from_secs(60),
                    user_provider.clone(),
                    |_| true,
                ),
            )
            .await;
            assert_eq!(replace_id, cancel_replace_event.replace_id);
            assert_eq!(issue_id, cancel_issue_event.issue_id);

            // not make sure we can cancel the redeem
            user_provider.cancel_redeem(redeem_id, true).await.unwrap();
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_auction_replace_succeeds() {
    // register two vaults. Issue with old_vault at capacity. Change exchange rate such that new_vault
    // will auction_replace.

    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    new_vault_provider
        .register_vault(vault_collateral * 2, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    let (replace_event_tx, _) = mpsc::channel::<RequestEvent>(16);
    test_service(
        try_join(
            vault::service::monitor_collateral_of_vaults(
                new_vault_provider.clone(),
                btc_rpc.clone(),
                replace_event_tx.clone(),
                Duration::from_secs(1),
            ),
            vault::service::listen_for_auction_replace(old_vault_provider.clone(), btc_rpc.clone(), 0),
        ),
        async {
            let old_vault_id = old_vault_provider.get_account_id();
            let new_vault_id = new_vault_provider.get_account_id();

            join3(
                // we need to go from 150% collateral to just below 120%. So increase dot-per-btc by just over 25%
                relayer_provider
                    .set_exchange_rate_info(FixedU128::saturating_from_rational(126u128, 10000u128))
                    .map(Result::unwrap),
                assert_event::<AuctionReplaceEvent<PolkaBtcRuntime>, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                    &e.old_vault_id == old_vault_id
                }),
                assert_event::<ExecuteReplaceEvent<PolkaBtcRuntime>, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                    &e.new_vault_id == new_vault_id
                }),
            )
            .await;
        },
    )
    .await;

    // check that the auctioned vault is still able to operate
    let vault_collateral = get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .lock_additional_collateral(vault_collateral)
        .await
        .unwrap();
    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_refund_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let refund_service = vault::service::listen_for_refund_requests(vault_provider.clone(), btc_rpc.clone(), 0);

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let vault_id = vault_provider.get_account_id().clone();
    let fut_user = async {
        let over_payment = 10000;

        let issue = user_provider
            .request_issue(issue_amount, vault_provider.get_account_id().clone(), 10000)
            .await
            .unwrap();

        let metadata = btc_rpc
            .send_to_address(
                issue.vault_btc_address,
                issue.amount_btc as u64 + over_payment,
                None,
                TIMEOUT,
                0,
            )
            .await
            .unwrap();

        let (_, refund_request, refund_execution) = join3(
            user_provider.execute_issue(
                issue.issue_id,
                metadata.txid.translate(),
                metadata.proof,
                metadata.raw_tx,
            ),
            assert_event::<RequestRefundEvent<PolkaBtcRuntime>, _>(TIMEOUT, user_provider.clone(), |x| {
                x.vault_id == vault_id
            }),
            assert_event::<ExecuteRefundEvent<PolkaBtcRuntime>, _>(TIMEOUT, user_provider.clone(), |_| true),
        )
        .await;

        assert_eq!(refund_request.refund_id, refund_execution.refund_id);
        assert_eq!(refund_execution.amount, (over_payment as f64 * 0.995) as u128);
    };

    test_service(refund_service, fut_user).await;
}

#[tokio::test(threaded_scheduler)]
async fn test_issue_overpayment_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let refund_service = vault::service::listen_for_refund_requests(vault_provider.clone(), btc_rpc.clone(), 0);

    let issue_amount = 100000;
    let over_payment_factor = 3;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault_provider, issue_amount * over_payment_factor).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let _vault_id = vault_provider.get_account_id().clone();
    let fut_user = async {
        let issue = user_provider
            .request_issue(issue_amount, vault_provider.get_account_id().clone(), 10000)
            .await
            .unwrap();

        let metadata = btc_rpc
            .send_to_address(
                issue.vault_btc_address,
                issue.amount_btc as u64 * over_payment_factor as u64,
                None,
                TIMEOUT,
                0,
            )
            .await
            .unwrap();

        join(
            assert_event::<MintEvent<PolkaBtcRuntime>, _>(TIMEOUT, user_provider.clone(), |x| {
                if &x.account_id == user_provider.get_account_id() {
                    // allow rounding errors
                    assert_eq!(x.amount, issue_amount * over_payment_factor);
                    true
                } else {
                    false
                }
            }),
            user_provider
                .execute_issue(
                    issue.issue_id,
                    metadata.txid.translate(),
                    metadata.proof,
                    metadata.raw_tx,
                )
                .map(Result::unwrap),
        )
        .await;
    };

    test_service(refund_service, fut_user).await;
}

#[tokio::test(threaded_scheduler)]
async fn test_automatic_issue_execution_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let vault1_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let vault2_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault1_provider, issue_amount).await;
    vault1_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    vault2_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let fut_user = async {
        let issue = user_provider
            .request_issue(issue_amount, vault1_provider.get_account_id().clone(), 10000)
            .await
            .unwrap();

        btc_rpc
            .send_to_address(issue.vault_btc_address, issue.amount_btc as u64, None, TIMEOUT, 0)
            .await
            .unwrap();

        // wait for vault2 to execute this issue
        let vault_id = vault1_provider.get_account_id().clone();
        assert_event::<ExecuteIssueEvent<PolkaBtcRuntime>, _>(TIMEOUT, user_provider.clone(), move |x| {
            x.vault_id == vault_id
        })
        .await;
    };

    let issue_set = Arc::new(IssueRequests::new());
    let (issue_event_tx, _issue_event_rx) = mpsc::channel::<RequestEvent>(16);
    let service = join(
        vault::service::listen_for_issue_requests(
            vault2_provider.clone(),
            btc_rpc.clone(),
            issue_event_tx.clone(),
            issue_set.clone(),
        ),
        vault::service::execute_open_issue_requests(vault2_provider.clone(), btc_rpc.clone(), issue_set.clone(), 0),
    );

    test_service(service, fut_user).await;
}

#[tokio::test(threaded_scheduler)]
async fn test_execute_open_requests_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    relayer_provider.register_staked_relayer(MINIMUM_STAKE).await.unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    assert_issue(&user_provider, &btc_rpc, vault_provider.get_account_id(), issue_amount).await;

    let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
    // place replace requests
    let redeem_ids = futures::future::join_all(
        (0..3u128).map(|_| user_provider.request_redeem(10000, address, vault_provider.get_account_id().clone())),
    )
    .await
    .into_iter()
    .map(|x| x.unwrap())
    .collect::<Vec<_>>();

    // send btc for redeem 0
    btc_rpc
        .send_to_address(address, 10000, Some(redeem_ids[0]), TIMEOUT, 0)
        .await
        .unwrap();

    let transaction = btc_rpc
        .create_transaction(address, 10000, Some(redeem_ids[1]))
        .await
        .unwrap()
        .transaction;
    btc_rpc.send_to_mempool(transaction).await;

    join3(
        vault::service::execute_open_requests(vault_provider, btc_rpc.clone(), 0).map(Result::unwrap),
        assert_redeem_event(TIMEOUT, user_provider.clone(), redeem_ids[0]),
        assert_redeem_event(TIMEOUT, user_provider.clone(), redeem_ids[2]),
    )
    .await;

    // now move from mempool into chain and await the remaining redeem
    btc_rpc.flush_mempool().await;
    assert_redeem_event(TIMEOUT, user_provider, redeem_ids[1]).await;
}

async fn assert_redeem_event(
    duration: Duration,
    provider: PolkaBtcProvider,
    redeem_id: H256,
) -> ExecuteRedeemEvent<PolkaBtcRuntime> {
    assert_event::<ExecuteRedeemEvent<PolkaBtcRuntime>, _>(duration, provider, |x| x.redeem_id == redeem_id).await
}
