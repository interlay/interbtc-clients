use async_trait::async_trait;
use bitcoin::{stream_blocks, SatPerVbyte};
use frame_support::assert_ok;
use futures::{
    channel::mpsc,
    future::{join, join3, join5},
    Future, FutureExt, SinkExt, TryStreamExt,
};
use runtime::{
    integration::*,
    sp_core::{H160, H256},
    subxt::utils::Static,
    types::*,
    utils::account_id::AccountId32,
    BtcAddress, CurrencyId, FixedPointNumber, FixedU128, InterBtcParachain, InterBtcRedeemRequest, IssuePallet,
    OraclePallet, PartialAddress, RedeemPallet, ReplacePallet, ShutdownSender, SudoPallet, UtilFuncs, VaultId,
    VaultRegistryPallet,
};
use service::DynBitcoinCoreApi;
use sp_keyring::AccountKeyring;
use std::{sync::Arc, time::Duration};
use vault::{self, Event as CancellationEvent, IssueRequests, VaultIdManager, ZeroDelay};

const TIMEOUT: Duration = Duration::from_secs(90);

const DEFAULT_NATIVE_CURRENCY: CurrencyId = Token(KINT);
const DEFAULT_TESTING_CURRENCY: CurrencyId = Token(KSM);
const DEFAULT_WRAPPED_CURRENCY: CurrencyId = Token(KBTC);

async fn test_with_vault<F, R>(execute: impl FnOnce(SubxtClient, VaultId, InterBtcParachain) -> F) -> R
where
    F: Future<Output = R>,
{
    service::init_subscriber();
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Alice).await;
    parachain_rpc
        .set_balances(
            vec![
                AccountKeyring::Alice,
                AccountKeyring::Bob,
                AccountKeyring::Charlie,
                AccountKeyring::Dave,
                AccountKeyring::Eve,
                AccountKeyring::Ferdie,
            ]
            .into_iter()
            .map(|keyring| keyring.to_account_id())
            .flat_map(|account_id| {
                vec![DEFAULT_TESTING_CURRENCY, DEFAULT_NATIVE_CURRENCY]
                    .into_iter()
                    .map(move |currency_id| (account_id.clone().into(), 1 << 60, 0, currency_id))
            })
            .collect::<Vec<(AccountId32, u128, u128, CurrencyId)>>(),
        )
        .await
        .expect("Should endow accounts");
    parachain_rpc
        .disable_difficulty_check()
        .await
        .expect("Should disable difficulty check");

    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Bob).await;
    set_exchange_rate_and_wait(&parachain_rpc, DEFAULT_TESTING_CURRENCY, FixedU128::from(100000000)).await;
    set_exchange_rate_and_wait(
        &parachain_rpc,
        DEFAULT_NATIVE_CURRENCY,
        FixedU128::saturating_from_rational(1u128, 100u128),
    )
    .await;
    set_bitcoin_fees(&parachain_rpc, FixedU128::from(1)).await;

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let vault_id = VaultId::new(
        AccountKeyring::Charlie.into(),
        DEFAULT_TESTING_CURRENCY,
        DEFAULT_WRAPPED_CURRENCY,
    );

    execute(client, vault_id, vault_provider).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_redeem_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(
            vault_provider.clone(),
            btc_rpc_master_wallet.clone(),
            btc_rpc_master_wallet,
            btc_rpcs,
            "test_redeem_succeeds",
        );

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        tracing::error!("vault_collateral: {vault_collateral}");

        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        let shutdown_tx = ShutdownSender::new();

        test_service(
            join(
                vault::service::listen_for_redeem_requests(
                    shutdown_tx,
                    vault_provider.clone(),
                    vault_id_manager,
                    0,
                    Duration::from_secs(0),
                    true,
                ),
                periodically_produce_blocks(user_provider.clone()),
            ),
            async {
                let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
                let redeem_id = user_provider.request_redeem(10000, address, &vault_id).await.unwrap();
                assert_redeem_event(TIMEOUT, user_provider, redeem_id).await;
                // TODO: check bitcoin payment amount
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_replace_succeeds() {
    test_with_vault(|client, old_vault_id, old_vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let new_vault_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let btc_rpcs = vec![(new_vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let new_btc_rpc_master_wallet = btc_rpc.clone();
        let _vault_id_manager = VaultIdManager::from_map(
            new_vault_provider.clone(),
            new_btc_rpc_master_wallet.clone(),
            new_btc_rpc_master_wallet,
            btc_rpcs,
            "test_replace_succeeds1",
        );
        let btc_rpcs = vec![
            (old_vault_id.clone(), btc_rpc.clone()),
            (new_vault_id.clone(), btc_rpc.clone()),
        ]
        .into_iter()
        .collect();
        let old_btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(
            old_vault_provider.clone(),
            old_btc_rpc_master_wallet.clone(),
            old_btc_rpc_master_wallet,
            btc_rpcs,
            "test_replace_succeeds2",
        );

        let issue_amount = 100000;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &old_vault_provider,
            issue_amount,
            old_vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            old_vault_provider
                .register_vault_with_public_key(
                    &old_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );
        assert_ok!(
            new_vault_provider
                .register_vault_with_public_key(
                    &new_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &old_vault_id, issue_amount).await;

        let shutdown_tx = ShutdownSender::new();
        let (replace_event_tx, _) = mpsc::channel::<CancellationEvent>(16);
        test_service(
            join3(
                vault::service::listen_for_replace_requests(
                    new_vault_provider.clone(),
                    vault_id_manager.clone(),
                    replace_event_tx.clone(),
                    true,
                ),
                vault::service::listen_for_accept_replace(
                    shutdown_tx.clone(),
                    old_vault_provider.clone(),
                    vault_id_manager.clone(),
                    0,
                    Duration::from_secs(0),
                    true,
                ),
                periodically_produce_blocks(old_vault_provider.clone()),
            ),
            async {
                old_vault_provider
                    .request_replace(&old_vault_id, issue_amount)
                    .await
                    .unwrap();

                assert_event::<AcceptReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                    assert_eq!(e.old_vault_id, old_vault_id);
                    assert_eq!(e.new_vault_id, new_vault_id);
                    true
                })
                .await;
                assert_event::<ExecuteReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                    assert_eq!(e.old_vault_id, old_vault_id);
                    assert_eq!(e.new_vault_id, new_vault_id);
                    true
                })
                .await;
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_withdraw_replace_succeeds() {
    test_with_vault(|client, old_vault_id, old_vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let new_vault_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let issue_amount = 100000;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &old_vault_provider,
            issue_amount,
            old_vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            old_vault_provider
                .register_vault_with_public_key(
                    &old_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );
        assert_ok!(
            new_vault_provider
                .register_vault_with_public_key(
                    &new_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &old_vault_id, issue_amount).await;

        join(
            old_vault_provider
                .request_replace(&old_vault_id, issue_amount)
                .map(Result::unwrap),
            assert_event::<RequestReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |_| true),
        )
        .await;

        join(
            old_vault_provider
                .withdraw_replace(&old_vault_id, issue_amount)
                .map(Result::unwrap),
            assert_event::<WithdrawReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                assert_eq!(e.old_vault_id, old_vault_id);
                true
            }),
        )
        .await;

        let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
        assert!(new_vault_provider
            .accept_replace(&new_vault_id, &old_vault_id, 1u32.into(), vault_collateral, address)
            .await
            .is_err());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cancellation_succeeds() {
    // tests cancellation of issue, redeem and replace.
    // issue and replace cancellation is tested through the vault's cancellation service.
    // cancel_redeem is called manually
    test_with_vault(|client, old_vault_id, old_vault_provider| async move {
        let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let new_vault_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let btc_rpcs = vec![(new_vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let new_btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(
            new_vault_provider.clone(),
            new_btc_rpc_master_wallet.clone(),
            new_btc_rpc_master_wallet,
            btc_rpcs,
            "test_cancellation_succeeds",
        );

        let issue_amount = 100000;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &old_vault_provider,
            issue_amount * 10,
            old_vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            old_vault_provider
                .register_vault_with_public_key(
                    &old_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );
        assert_ok!(
            new_vault_provider
                .register_vault_with_public_key(
                    &new_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &old_vault_id, issue_amount).await;

        // set low timeout periods
        assert_ok!(root_provider.set_issue_period(1).await);
        assert_ok!(root_provider.set_replace_period(1).await);
        assert_ok!(root_provider.set_redeem_period(1).await);

        let (issue_cancellation_event_tx, issue_cancellation_rx) = mpsc::channel::<CancellationEvent>(16);
        let (replace_cancellation_event_tx, replace_cancellation_rx) = mpsc::channel::<CancellationEvent>(16);

        let block_listener = new_vault_provider.clone();
        let issue_set = Arc::new(IssueRequests::new());

        let issue_request_listener = vault::service::listen_for_issue_requests(
            vault_id_manager.clone(),
            new_vault_provider.clone(),
            issue_cancellation_event_tx.clone(),
            issue_set.clone(),
        );

        let issue_cancellation_scheduler = vault::service::CancellationScheduler::new(
            new_vault_provider.clone(),
            new_vault_provider.get_current_chain_height().await.unwrap(),
            0,
            new_vault_provider.get_account_id().clone(),
        );
        let replace_cancellation_scheduler = vault::service::CancellationScheduler::new(
            new_vault_provider.clone(),
            new_vault_provider.get_current_chain_height().await.unwrap(),
            0,
            new_vault_provider.get_account_id().clone(),
        );
        let issue_canceller =
            issue_cancellation_scheduler.handle_cancellation::<vault::service::IssueCanceller>(issue_cancellation_rx);
        let replace_canceller = replace_cancellation_scheduler
            .handle_cancellation::<vault::service::ReplaceCanceller>(replace_cancellation_rx);

        let parachain_block_listener = async {
            let issue_block_tx = &issue_cancellation_event_tx.clone();
            let replace_block_tx = &replace_cancellation_event_tx.clone();

            block_listener
                .clone()
                .on_event::<UpdateActiveBlockEvent, _, _, _>(
                    |event| async move {
                        assert_ok!(
                            issue_block_tx
                                .clone()
                                .send(CancellationEvent::ParachainBlock(event.block_number))
                                .await
                        );
                        assert_ok!(
                            replace_block_tx
                                .clone()
                                .send(CancellationEvent::ParachainBlock(event.block_number))
                                .await
                        );
                    },
                    |_err| (),
                )
                .await
                .unwrap();
        };

        let initial_btc_height = btc_rpc.get_block_count().await.unwrap() as u32;
        let bitcoin_block_listener = async {
            let issue_block_tx = &issue_cancellation_event_tx.clone();
            let replace_block_tx = &replace_cancellation_event_tx.clone();

            stream_blocks(btc_rpc.clone(), initial_btc_height, 1)
                .await
                .try_for_each(|_| async {
                    let height = btc_rpc.get_block_count().await? as u32;
                    let _ = issue_block_tx
                        .clone()
                        .send(CancellationEvent::BitcoinBlock(height))
                        .await;
                    let _ = replace_block_tx
                        .clone()
                        .send(CancellationEvent::BitcoinBlock(height))
                        .await;
                    Ok(())
                })
                .await
                .unwrap();
        };

        test_service(
            join5(
                issue_canceller.map(Result::unwrap),
                replace_canceller.map(Result::unwrap),
                issue_request_listener.map(Result::unwrap),
                parachain_block_listener,
                bitcoin_block_listener,
            ),
            async {
                let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));

                // setup the to-be-cancelled redeem
                let redeem_id = user_provider
                    .request_redeem(20000, address, &old_vault_id)
                    .await
                    .unwrap();

                join3(
                    async {
                        // setup the to-be-cancelled replace
                        assert_ok!(
                            old_vault_provider
                                .request_replace(&old_vault_id, issue_amount / 2)
                                .await
                        );
                        assert_ok!(
                            new_vault_provider
                                .accept_replace(&new_vault_id, &old_vault_id, 10000000u32.into(), 0u32.into(), address)
                                .await
                        );
                        assert_ok!(
                            replace_cancellation_event_tx
                                .clone()
                                .send(CancellationEvent::Opened)
                                .await
                        );

                        // setup the to-be-cancelled issue
                        assert_ok!(user_provider.request_issue(issue_amount, &new_vault_id).await);

                        for _ in 0u32..2 {
                            assert_ok!(
                                btc_rpc
                                    .send_to_address(
                                        BtcAddress::P2PKH(H160::from_slice(&[0; 20]))
                                            .to_address(btc_rpc.network())
                                            .unwrap(),
                                        100_000,
                                        None,
                                        SatPerVbyte(1000),
                                        1
                                    )
                                    .await
                            );
                        }
                    },
                    assert_event::<CancelIssueEvent, _>(Duration::from_secs(120), user_provider.clone(), |_| true),
                    assert_event::<CancelReplaceEvent, _>(Duration::from_secs(120), user_provider.clone(), |_| true),
                )
                .await;

                // now make sure we can cancel the redeem
                assert_ok!(user_provider.cancel_redeem(redeem_id, true).await);
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_issue_overpayment_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let issue_amount = 100000;
        let over_payment_factor = 3;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &vault_provider,
            issue_amount * over_payment_factor,
            vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        let issue = user_provider.request_issue(issue_amount, &vault_id).await.unwrap();

        let metadata = btc_rpc
            .send_to_address(
                issue.vault_address.to_address(btc_rpc.network()).unwrap(),
                (issue.amount + issue.fee) as u64 * over_payment_factor as u64,
                None,
                SatPerVbyte(1000),
                0,
            )
            .await
            .unwrap();

        join(
            assert_event::<EndowedEvent, _>(TIMEOUT, user_provider.clone(), |x| {
                if &x.who == user_provider.get_account_id() {
                    assert_eq!(x.amount, issue.amount * over_payment_factor);
                    true
                } else {
                    false
                }
            }),
            user_provider
                .execute_issue(*issue.issue_id, &metadata.proof, &metadata.raw_tx)
                .map(Result::unwrap),
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_automatic_issue_execution_succeeds() {
    test_with_vault(|client, vault1_id, _vault1_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let vault1_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
        let vault2_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let vault2_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let btc_rpcs = vec![(vault2_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(
            vault2_provider.clone(),
            btc_rpc_master_wallet.clone(),
            btc_rpc_master_wallet,
            btc_rpcs,
            "test_automatic_issue_execution_succeeds",
        );

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault1_provider, issue_amount, vault1_id.collateral_currency())
                .await;

        assert_ok!(
            vault1_provider
                .register_vault_with_public_key(
                    &vault1_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );
        assert_ok!(
            vault2_provider
                .register_vault_with_public_key(
                    &vault2_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        let fut_user = async {
            let issue = user_provider.request_issue(issue_amount, &vault1_id).await.unwrap();
            tracing::warn!("REQUESTED ISSUE: {:?}", issue);

            assert_ok!(
                btc_rpc
                    .send_to_address(
                        issue.vault_address.to_address(btc_rpc.network()).unwrap(),
                        (issue.amount + issue.fee) as u64,
                        None,
                        SatPerVbyte(1000),
                        0
                    )
                    .await
            );

            // wait for vault2 to execute this issue
            assert_event::<ExecuteIssueEvent, _>(TIMEOUT, user_provider.clone(), move |x| {
                x.vault_id == vault1_id.clone()
            })
            .await;
        };

        let issue_set = Arc::new(IssueRequests::new());
        let (issue_event_tx, _issue_event_rx) = mpsc::channel::<CancellationEvent>(16);
        let service = join3(
            vault::service::listen_for_issue_requests(
                vault_id_manager.clone(),
                vault2_provider.clone(),
                issue_event_tx.clone(),
                issue_set.clone(),
            ),
            vault::service::process_issue_requests(
                btc_rpc.clone(),
                vault2_provider.clone(),
                issue_set.clone(),
                1,
                0,
                Arc::new(Box::new(ZeroDelay)),
            ),
            periodically_produce_blocks(vault2_provider.clone()),
        );

        test_service(service, fut_user).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
// todo: refactor to reuse code from test_automatic_issue_execution_succeeds
async fn test_automatic_issue_execution_succeeds_with_big_transaction() {
    test_with_vault(|client, vault1_id, _vault1_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let vault1_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
        let vault2_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let vault2_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core.clone());

        let btc_rpcs = vec![(vault2_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(
            vault2_provider.clone(),
            btc_rpc_master_wallet.clone(),
            btc_rpc_master_wallet,
            btc_rpcs,
            "test_automatic_issue_execution_succeeds_with_big_transaction",
        );

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault1_provider, issue_amount, vault1_id.collateral_currency())
                .await;
        assert_ok!(
            vault1_provider
                .register_vault_with_public_key(
                    &vault1_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );
        assert_ok!(
            vault2_provider
                .register_vault_with_public_key(
                    &vault2_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        let fut_user = async {
            let issue = user_provider.request_issue(issue_amount, &vault1_id).await.unwrap();
            tracing::warn!("REQUESTED ISSUE: {:?}", issue);

            assert_ok!(
                mock_bitcoin_core
                    .send_to_address_with_many_outputs(
                        issue.vault_address.to_address(btc_rpc.network()).unwrap(),
                        (issue.amount + issue.fee) as u64,
                        None,
                        SatPerVbyte(1000),
                        0
                    )
                    .await
            );

            // wait for vault2 to execute this issue
            assert_event::<ExecuteIssueEvent, _>(TIMEOUT, user_provider.clone(), move |x| x.vault_id == vault1_id)
                .await;
        };

        let issue_set = Arc::new(IssueRequests::new());
        let (issue_event_tx, _issue_event_rx) = mpsc::channel::<CancellationEvent>(16);
        let service = join3(
            vault::service::listen_for_issue_requests(
                vault_id_manager.clone(),
                vault2_provider.clone(),
                issue_event_tx.clone(),
                issue_set.clone(),
            ),
            vault::service::process_issue_requests(
                btc_rpc.clone(),
                vault2_provider.clone(),
                issue_set.clone(),
                1,
                0,
                Arc::new(Box::new(ZeroDelay)),
            ),
            periodically_produce_blocks(vault2_provider.clone()),
        );

        test_service(service, fut_user).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_execute_open_requests_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core.clone());

        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(
            vault_provider.clone(),
            btc_rpc_master_wallet.clone(),
            btc_rpc_master_wallet,
            btc_rpcs,
            "test_execute_open_requests_succeeds",
        );

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
        // place replace requests
        let redeem_ids =
            futures::future::join_all((0..3u128).map(|_| user_provider.request_redeem(10000, address, &vault_id)))
                .await
                .into_iter()
                .map(|x| x.unwrap())
                .collect::<Vec<_>>();

        let redeems: Vec<InterBtcRedeemRequest> =
            futures::future::join_all(redeem_ids.iter().map(|id| user_provider.get_redeem_request(*id)))
                .await
                .into_iter()
                .map(|x| x.unwrap())
                .collect::<Vec<_>>();

        // send btc for redeem 0
        assert_ok!(
            btc_rpc
                .send_to_address(
                    address.to_address(btc_rpc.network()).unwrap(),
                    redeems[0].amount_btc as u64,
                    Some(redeem_ids[0]),
                    SatPerVbyte(1000),
                    0
                )
                .await
        );

        let transaction = mock_bitcoin_core
            .create_transaction(
                address.to_address(btc_rpc.network()).unwrap(),
                redeems[1].amount_btc as u64,
                SatPerVbyte(1000),
                Some(redeem_ids[1]),
            )
            .await
            .unwrap();
        mock_bitcoin_core.send_to_mempool(transaction).await;

        let shutdown_tx = ShutdownSender::new();
        join3(
            vault::service::execute_open_requests(
                shutdown_tx.clone(),
                vault_provider,
                vault_id_manager,
                btc_rpc.clone(),
                0,
                Duration::from_secs(0),
                true,
            )
            .map(Result::unwrap),
            assert_redeem_event(TIMEOUT, user_provider.clone(), redeem_ids[0]),
            assert_redeem_event(TIMEOUT, user_provider.clone(), redeem_ids[2]),
        )
        .await;

        // now move from mempool into chain and await the remaining redeem
        mock_bitcoin_core.flush_mempool().await;
        test_service(
            periodically_produce_blocks(user_provider.clone()),
            assert_redeem_event(TIMEOUT, user_provider, redeem_ids[1]),
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_off_chain_liquidation() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let mock_bitcoin_core = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin_core);

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        set_exchange_rate_and_wait(&relayer_provider, DEFAULT_TESTING_CURRENCY, FixedU128::from(1000000000)).await;

        assert_event::<LiquidateVaultEvent, _>(TIMEOUT, vault_provider.clone(), |_| true).await;
    })
    .await;
}

async fn assert_redeem_event(
    duration: Duration,
    parachain_rpc: InterBtcParachain,
    redeem_id: H256,
) -> ExecuteRedeemEvent {
    assert_event::<ExecuteRedeemEvent, _>(duration, parachain_rpc, |x| x.redeem_id == Static(redeem_id)).await
}

#[async_trait]
trait InterBtcParachainExt {
    async fn register_vault_with_public_key(
        &self,
        vault_id: &VaultId,
        collateral: u128,
        public_key: BtcPublicKey,
    ) -> Result<(), runtime::Error>;
}

#[async_trait]
impl InterBtcParachainExt for InterBtcParachain {
    async fn register_vault_with_public_key(
        &self,
        vault_id: &VaultId,
        collateral: u128,
        public_key: BtcPublicKey,
    ) -> Result<(), runtime::Error> {
        self.register_public_key(public_key).await.unwrap();
        self.register_vault(vault_id, collateral).await.unwrap();
        Ok(())
    }
}

#[cfg(feature = "uses-bitcoind")]
mod test_with_bitcoind {
    use bitcoin::{BitcoinCore, BitcoinCoreApi, Transaction, TransactionExt};
    use runtime::BtcRelayPallet;
    use vault::service::Runner;

    use std::cmp::max;
    use vault::{delay::ZeroDelay, relay::Config};

    use super::*;

    async fn get_bitcoin_core() -> BitcoinCore {
        use bitcoin::{cli::BitcoinOpts, Network};
        use std::env::var;

        let opts = BitcoinOpts {
            bitcoin_rpc_url: Some(var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL not set").to_string()),
            bitcoin_rpc_user: Some(var("BITCOIN_RPC_USER").expect("BITCOIN_RPC_USER not set").to_string()),
            bitcoin_rpc_pass: Some(var("BITCOIN_RPC_PASS").expect("BITCOIN_RPC_PASS not set").to_string()),
            bitcoin_connection_timeout_ms: 10000,
            electrs_url: None,
            ..Default::default()
        };
        let ret = opts
            .new_client_builder(Some("regtest-wallet".to_string()))
            .build_with_network(Network::Regtest)
            .unwrap();
        ret.create_or_load_wallet().await.unwrap();

        // fund the wallet by mining blocks
        for _ in 0..102 {
            ret.mine_block().unwrap();
        }

        ret
    }

    /// request, pay and execute an issue
    pub async fn assert_issue_bitcoind(
        parachain_rpc: &InterBtcParachain,
        bitcoin_core: &BitcoinCore,
        vault_id: &VaultId,
        amount: u128,
    ) {
        let issue = parachain_rpc.request_issue(amount, vault_id).await.unwrap();

        let fee_rate = SatPerVbyte(1000);

        // if auto-mining somehow is not enabled
        // we should timeout this call
        let metadata = with_timeout(
            bitcoin_core.send_to_address(
                issue.vault_address.to_address(bitcoin_core.network()).unwrap(),
                (issue.amount + issue.fee) as u64,
                None,
                fee_rate,
                0,
            ),
            TIMEOUT,
        )
        .await
        .unwrap();

        parachain_rpc
            .wait_for_block_in_relay(H256Le::from_bytes_le(&metadata.block_hash), Some(0))
            .await
            .unwrap();

        parachain_rpc
            .execute_issue(*issue.issue_id, &metadata.proof, &metadata.raw_tx)
            .await
            .unwrap();
    }

    fn extract_output_addresses(tx: &Transaction) -> Vec<BtcAddress> {
        tx.extract_output_addresses()
            .into_iter()
            .filter_map(|payload| BtcAddress::from_payload(payload).ok())
            .collect()
    }

    #[tracing::instrument(skip(user_provider, relayer_provider, btc_rpc, vault_id))]
    async fn test_execute_redeem_succeeds_after_non_increasing_fee_change(
        user_provider: InterBtcParachain,
        relayer_provider: InterBtcParachain,
        btc_rpc: BitcoinCore,
        vault_id: VaultId,
    ) {
        let address = BtcAddress::P2PKH(H160::random());
        set_bitcoin_fees(&relayer_provider, FixedU128::from(3)).await;

        let redeem_id = user_provider.request_redeem(10000, address, &vault_id).await.unwrap();

        tracing::trace!("Step 1: waiting for initial tx...");
        let initial_tx = loop {
            match btc_rpc
                .get_mempool_transactions()
                .await
                .unwrap()
                .map(|tx| tx.unwrap())
                .find(|tx| {
                    let addresses = extract_output_addresses(tx);
                    addresses.into_iter().any(|x| x == address)
                }) {
                None => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Some(tx) => break tx,
            }
        };

        tracing::trace!("Step 2: update bitcoin fees");
        set_bitcoin_fees(&relayer_provider, FixedU128::from(3)).await; // no change
        set_bitcoin_fees(&relayer_provider, FixedU128::from(2)).await; // decrease
        set_bitcoin_fees(&relayer_provider, FixedU128::from(1000000000)).await; // such a high increase that vault is not able to pay the fees

        // give redeem handler time to react
        tokio::time::sleep(Duration::from_secs(1)).await;

        tracing::trace!("Step 3: check that no other transactions were made");
        assert!(!btc_rpc
            .get_mempool_transactions()
            .await
            .unwrap()
            .map(|tx| tx.unwrap())
            .filter(|tx| tx != &initial_tx)
            .any(|tx| {
                let addresses = extract_output_addresses(&tx);
                addresses.into_iter().any(|x| x == address)
            }));

        tracing::trace!("Step 4: mine bitcoin block");
        let block_hash = btc_rpc.mine_block().unwrap();

        tracing::info!("Step 5: check that tx got included without changes");
        btc_rpc
            .get_transaction(&initial_tx.txid(), Some(block_hash))
            .await
            .unwrap();

        tracing::trace!("Step 6: check redeem event");
        assert_redeem_event(TIMEOUT, user_provider, redeem_id).await;
    }

    #[tracing::instrument(skip(user_provider, relayer_provider, btc_rpc, vault_id))]
    async fn test_execute_redeem_succeeds_after_fee_bump(
        user_provider: InterBtcParachain,
        relayer_provider: InterBtcParachain,
        btc_rpc: BitcoinCore,
        vault_id: VaultId,
    ) {
        set_bitcoin_fees(&relayer_provider, FixedU128::from(1)).await;

        let address = BtcAddress::P2PKH(H160::random());
        let redeem_id = user_provider.request_redeem(10000, address, &vault_id).await.unwrap();

        tracing::trace!("Step 1: waiting for initial tx...");
        let initial_tx = loop {
            match btc_rpc
                .get_mempool_transactions()
                .await
                .unwrap()
                .map(|tx| tx.unwrap())
                .find(|tx| {
                    let addresses = extract_output_addresses(tx);
                    addresses.into_iter().any(|x| x == address)
                }) {
                None => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Some(tx) => break tx,
            }
        };

        tracing::trace!("Step 2: signal an increase in bitcoin fees");
        set_bitcoin_fees(&relayer_provider, FixedU128::from(10)).await;

        tracing::trace!("Step 3: wait for new tx in mempool");
        let new_tx = loop {
            match btc_rpc
                .get_mempool_transactions()
                .await
                .unwrap()
                .map(|tx| tx.unwrap())
                .filter(|tx| tx != &initial_tx)
                .find(|tx| {
                    let addresses = extract_output_addresses(tx);
                    addresses.into_iter().any(|x| x == address)
                }) {
                None => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Some(tx) => break tx,
            }
        };

        tracing::trace!("Step 4: check fee rate");
        // don't check for strict equality - sometimes bitcoin core decides to use
        // a higher fee
        assert!(btc_rpc.fee_rate(new_tx.txid()).await.unwrap().0 >= 10);

        tracing::trace!("Step 5: mine bitcoin block");
        let block_hash = btc_rpc.mine_block().unwrap();

        tracing::trace!("Step 6: check that only new tx got included");
        btc_rpc.get_transaction(&new_tx.txid(), Some(block_hash)).await.unwrap();
        assert!(btc_rpc.get_transaction(&initial_tx.txid(), None).await.is_err());

        tracing::trace!("Step 7: check redeem event");
        assert_redeem_event(TIMEOUT, user_provider, redeem_id).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_automatic_rbf_succeeds() {
        use vault::relay::run_relayer;

        test_with_vault(|client, vault_id, vault_provider| async move {
            let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
            let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

            let mut bitcoin_core = get_bitcoin_core().await;
            let btc_rpc: DynBitcoinCoreApi = Arc::new(bitcoin_core.clone());

            let height = bitcoin_core.get_block_count().await.unwrap() as u32;
            let relayer = Runner::new(
                btc_rpc.clone(),
                user_provider.clone(),
                Config {
                    start_height: Some(max(1, height.saturating_sub(200))), /* important to skip the genesis block
                                                                             * since it has nVersion < 4, so it would
                                                                             * get rejected */
                    max_batch_size: 16,
                    interval: Some(std::time::Duration::from_secs(1)),
                    btc_confirmations: 0,
                },
                Arc::new(Box::new(ZeroDelay)),
            );

            tracing::trace!("Initializing relay");
            relayer.submit_next().await.unwrap(); // make sure the relay is initialized

            let parachain_miner = join(run_relayer(relayer), periodically_produce_blocks(user_provider.clone()));
            tokio::spawn(parachain_miner);

            // setup vault id manager
            let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
            let btc_rpc_master_wallet = btc_rpc.clone();
            let vault_id_manager = VaultIdManager::from_map(
                vault_provider.clone(),
                btc_rpc_master_wallet.clone(),
                btc_rpc_master_wallet,
                btc_rpcs,
                "test_automatic_rbf_succeeds",
            );

            let issue_amount = 100000;
            let vault_collateral =
                get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                    .await;

            tracing::trace!("Registering public key");
            assert_ok!(
                vault_provider
                    .register_vault_with_public_key(
                        &vault_id,
                        vault_collateral,
                        btc_rpc.get_new_public_key().await.unwrap().inner.serialize().into(),
                    )
                    .await
            );

            // set automining for the issue below. Note that the btc_rpc inside
            // vault_id_manager is a clone that still has auto mining disabled
            bitcoin_core.set_auto_mining(true);
            assert_issue_bitcoind(&user_provider, &bitcoin_core, &vault_id, issue_amount).await;

            // setup the service to test including necessary auxiliary services
            let shutdown_tx = ShutdownSender::new();
            let service = join(
                vault::service::listen_for_redeem_requests(
                    shutdown_tx,
                    vault_provider.clone(),
                    vault_id_manager,
                    0,
                    Duration::from_secs(0),
                    true,
                ),
                vault_provider.listen_for_fee_rate_changes(),
            );

            // setup the code we'll use to verify that rbf works
            let validation = async {
                // run these two tests sequentially for now since running these
                // concurrently would result in them interfering with each other.
                // Todo if we to have more tests with bitcoind is to treat mining
                // as a shared resource that tests can requests exclusive or
                // shared access to
                test_execute_redeem_succeeds_after_non_increasing_fee_change(
                    user_provider.clone(),
                    relayer_provider.clone(),
                    bitcoin_core.clone(),
                    vault_id.clone(),
                )
                .await;

                test_execute_redeem_succeeds_after_fee_bump(
                    user_provider.clone(),
                    relayer_provider.clone(),
                    bitcoin_core.clone(),
                    vault_id.clone(),
                )
                .await;
            };

            test_service(service, validation).await;
        })
        .await;
    }
}
