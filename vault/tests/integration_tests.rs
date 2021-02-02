mod bitcoin_simulator;
use bitcoin_simulator::*;

use bitcoin::{BitcoinCoreApi, Txid};
use futures::{
    channel::mpsc,
    future::{join, join3, join4, try_join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use jsonrpsee::Client as JsonRpseeClient;
use log::*;
use runtime::{
    pallets::{issue::*, redeem::*, refund::*, replace::*, treasury::*, vault_registry::*},
    substrate_subxt::{Event, PairSigner},
    AccountId, BtcAddress, ExchangeRateOraclePallet, FeePallet, FixedPointNumber, FixedU128,
    H256Le, IssuePallet, PolkaBtcHeader, PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet,
    ReplacePallet, UtilFuncs, VaultRegistryPallet,
};
use sp_core::H160;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;
use tokio::time::timeout;
use vault;
use vault::{IssueRequests, RequestEvent};

trait Translate {
    type Associated;
    fn translate(&self) -> Self::Associated;
}

impl Translate for Txid {
    type Associated = H256Le;
    fn translate(&self) -> Self::Associated {
        H256Le::from_bytes_le(&self.to_vec())
    }
}

async fn default_provider_client(key: AccountKeyring) -> (JsonRpseeClient, TempDir) {
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

    let client = SubxtClient::from_config(config, btc_parachain_service::new_full)
        .expect("Error creating subxt client")
        .into();
    return (client, tmp);
}

async fn setup_provider(client: JsonRpseeClient, key: AccountKeyring) -> Arc<PolkaBtcProvider> {
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());
    let ret = PolkaBtcProvider::new(client, signer)
        .await
        .expect("Error creating provider");
    Arc::new(ret)
}

async fn assert_issue(
    provider: &PolkaBtcProvider,
    btc_rpc: &MockBitcoinCore,
    vault_id: &AccountId,
    amount: u128,
) {
    let issue = provider
        .request_issue(amount, vault_id.clone(), 10000)
        .await
        .unwrap();

    let metadata = btc_rpc
        .send_to_address(
            issue.btc_address,
            issue.amount as u64,
            None,
            Duration::from_secs(30),
            0,
        )
        .await
        .unwrap();

    provider
        .execute_issue(
            issue.issue_id,
            metadata.txid.translate(),
            metadata.proof,
            metadata.raw_tx,
        )
        .await
        .unwrap();
}

async fn get_required_vault_collateral_for_issue(
    provider: &PolkaBtcProvider,
    amount: u128,
) -> u128 {
    let fee = provider.get_issue_fee().await.unwrap();
    let amount_btc_including_fee = amount + fee.checked_mul_int(amount).unwrap();
    provider
        .get_required_collateral_for_polkabtc(amount_btc_including_fee)
        .await
        .unwrap()
}

#[tokio::test(threaded_scheduler)]
async fn test_redeem_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    test_service(
        vault::service::listen_for_redeem_requests(vault_provider.clone(), btc_rpc, 0),
        async {
            let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
            let vault_id = vault_provider.clone().get_account_id().clone();
            let redeem_id = user_provider
                .request_redeem(10000, address, vault_id)
                .await
                .unwrap();
            assert_redeem_event(Duration::from_secs(30), user_provider, redeem_id).await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_replace_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();
    new_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
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
            vault::service::listen_for_accept_replace(
                old_vault_provider.clone(),
                btc_rpc.clone(),
                0,
            ),
        ),
        async {
            let replace_id = old_vault_provider
                .request_replace(issue_amount, 1000000)
                .await
                .unwrap();

            assert_event::<AcceptReplaceEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                old_vault_provider.clone(),
                |e| e.replace_id == replace_id,
            )
            .await;
            assert_event::<ExecuteReplaceEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                old_vault_provider.clone(),
                |e| e.replace_id == replace_id,
            )
            .await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_maintain_collateral_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    test_service(
        vault::service::maintain_collateralization_rate(vault_provider.clone(), 1000000000),
        async {
            // dot per btc increases by 10%
            relayer_provider
                .set_exchange_rate_info(FixedU128::saturating_from_rational(110u128, 10000))
                .await
                .unwrap();
            assert_event::<LockAdditionalCollateralEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                vault_provider.clone(),
                |e| {
                    assert_eq!(e.new_collateral, vault_collateral / 10);
                    true
                },
            )
            .await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_withdraw_replace_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();
    new_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    let replace_id = old_vault_provider
        .request_replace(issue_amount, 1000000)
        .await
        .unwrap();
    assert_event::<RequestReplaceEvent<PolkaBtcRuntime>, _>(
        Duration::from_secs(30),
        old_vault_provider.clone(),
        |e| e.replace_id == replace_id,
    )
    .await;
    old_vault_provider
        .withdraw_replace(replace_id)
        .await
        .unwrap();
    assert_event::<WithdrawReplaceEvent<PolkaBtcRuntime>, _>(
        Duration::from_secs(30),
        old_vault_provider.clone(),
        |e| e.request_id == replace_id,
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
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount * 10).await;
    old_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();
    new_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();

    // set low timeout periods
    root_provider.set_issue_period(2).await.unwrap();
    root_provider.set_replace_period(2).await.unwrap();
    root_provider.set_redeem_period(2).await.unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        old_vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

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
        .handle_cancellation::<vault::service::ReplaceCanceller>(
            replace_block_rx,
            replace_event_rx,
        );

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
            async { issue_canceller.await.unwrap() },
            async { replace_canceller.await.unwrap() },
            async { issue_request_listener.await.unwrap() },
            async { block_listener.await },
        ),
        async {
            let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));

            // setup the to-be-cancelled redeem
            let redeem_id = user_provider
                .request_redeem(20000, address, old_vault_provider.get_account_id().clone())
                .await
                .unwrap();

            // setup the to-be-cancelled replace
            let replace_id = old_vault_provider
                .request_replace(issue_amount / 2, 1000000)
                .await
                .unwrap();
            new_vault_provider
                .accept_replace(replace_id, 10000000, address)
                .await
                .unwrap();
            replace_event_tx
                .clone()
                .send(RequestEvent::Opened)
                .await
                .unwrap();

            // setup the to-be-cancelled issue
            let issue = user_provider
                .request_issue(
                    issue_amount,
                    new_vault_provider.get_account_id().clone(),
                    10000,
                )
                .await
                .unwrap();

            join(
                assert_event::<CancelIssueEvent<PolkaBtcRuntime>, _>(
                    Duration::from_secs(45),
                    user_provider.clone(),
                    |x| x.issue_id == issue.issue_id,
                ),
                assert_event::<CancelReplaceEvent<PolkaBtcRuntime>, _>(
                    Duration::from_secs(45),
                    user_provider.clone(),
                    |x| x.replace_id == replace_id,
                ),
            )
            .await;
            user_provider.cancel_redeem(redeem_id, true).await.unwrap();
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
#[ignore]
async fn test_auction_replace_succeeds() {
    // register two vaults. Issue with old_vault at capacity. Change exchange rate such that new_vault
    // will auction_replace.

    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let old_vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&old_vault_provider, issue_amount).await;
    old_vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();
    new_vault_provider
        .register_vault(
            vault_collateral * 2,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
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
            vault::service::listen_for_auction_replace(
                old_vault_provider.clone(),
                btc_rpc.clone(),
                0,
            ),
        ),
        async {
            let old_vault_id = old_vault_provider.get_account_id();
            let new_vault_id = new_vault_provider.get_account_id();
            relayer_provider
                .set_exchange_rate_info(FixedU128::saturating_from_rational(2u128, 100))
                .await
                .unwrap();

            assert_event::<AuctionReplaceEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                old_vault_provider.clone(),
                |e| &e.old_vault_id == old_vault_id,
            )
            .await;
            assert_event::<ExecuteReplaceEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                old_vault_provider.clone(),
                |e| &e.new_vault_id == new_vault_id,
            )
            .await;
        },
    )
    .await;
}

#[tokio::test(threaded_scheduler)]
async fn test_refund_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let refund_service =
        vault::service::listen_for_refund_requests(vault_provider.clone(), btc_rpc.clone(), 0);

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
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
                issue.btc_address,
                issue.amount as u64 + over_payment,
                None,
                Duration::from_secs(30),
                0,
            )
            .await
            .unwrap();

        let (refund_request, _) = join(
            assert_event::<RequestRefundEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                user_provider.clone(),
                |x| x.vault_id == vault_id,
            ),
            async {
                user_provider
                    .execute_issue(
                        issue.issue_id,
                        metadata.txid.translate(),
                        metadata.proof,
                        metadata.raw_tx,
                    )
                    .await
                    .unwrap();
            },
        )
        .await;

        assert_event::<ExecuteRefundEvent<PolkaBtcRuntime>, _>(
            Duration::from_secs(30),
            user_provider.clone(),
            |x| {
                if &x.refund_id == &refund_request.refund_id {
                    assert_eq!(x.amount, (over_payment as f64 * 0.995) as u128);
                    true
                } else {
                    false
                }
            },
        )
        .await;
    };

    test_service(refund_service, fut_user).await;
}

#[tokio::test(threaded_scheduler)]
async fn test_issue_overpayment_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let refund_service =
        vault::service::listen_for_refund_requests(vault_provider.clone(), btc_rpc.clone(), 0);

    let issue_amount = 100000;
    let over_payment_factor = 3;
    let vault_collateral = get_required_vault_collateral_for_issue(
        &vault_provider,
        issue_amount * over_payment_factor,
    )
    .await;
    vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
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
                issue.btc_address,
                issue.amount as u64 * over_payment_factor as u64,
                None,
                Duration::from_secs(30),
                0,
            )
            .await
            .unwrap();

        join(
            assert_event::<MintEvent<PolkaBtcRuntime>, _>(
                Duration::from_secs(30),
                user_provider.clone(),
                |x| {
                    if &x.account_id == user_provider.get_account_id() {
                        // allow rounding errors
                        assert_eq!(x.amount, issue_amount * over_payment_factor);
                        true
                    } else {
                        false
                    }
                },
            ),
            async {
                user_provider
                    .execute_issue(
                        issue.issue_id,
                        metadata.txid.translate(),
                        metadata.proof,
                        metadata.raw_tx,
                    )
                    .await
                    .unwrap()
            },
        )
        .await;
    };

    test_service(refund_service, fut_user).await;
}

#[tokio::test(threaded_scheduler)]
async fn test_automatic_issue_execution_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault1_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let vault2_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault1_provider, issue_amount).await;
    vault1_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();
    vault2_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();

    let fut_user = async {
        let issue = user_provider
            .request_issue(
                issue_amount,
                vault1_provider.get_account_id().clone(),
                10000,
            )
            .await
            .unwrap();

        btc_rpc
            .send_to_address(
                issue.btc_address,
                issue.amount as u64,
                None,
                Duration::from_secs(30),
                0,
            )
            .await
            .unwrap();

        // wait for vault2 to execute this issue
        let vault_id = vault1_provider.get_account_id().clone();
        assert_event::<ExecuteIssueEvent<PolkaBtcRuntime>, _>(
            Duration::from_secs(30),
            user_provider.clone(),
            move |x| x.vault_id == vault_id,
        )
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
        vault::service::execute_open_issue_requests(
            vault2_provider.clone(),
            btc_rpc.clone(),
            issue_set.clone(),
            0,
        ),
    );

    test_service(service, fut_user).await;
}

pub async fn test_service<T: Future, U: Future>(service: T, fut: U) -> U::Output {
    pin_mut!(service, fut);
    match futures::future::select(service, fut).await {
        Either::Right((ret, _)) => ret,
        _ => panic!(),
    }
}

#[tokio::test(threaded_scheduler)]
async fn test_execute_open_requests_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    let btc_rpc = Arc::new(MockBitcoinCore::new(relayer_provider.clone()).await);

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(
            vault_collateral,
            btc_rpc.get_new_public_key().await.unwrap(),
        )
        .await
        .unwrap();

    assert_issue(
        &user_provider,
        &btc_rpc,
        vault_provider.get_account_id(),
        issue_amount,
    )
    .await;

    let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
    // place replace requests
    let redeem_ids = futures::future::join_all((0..3u128).map(|_| {
        user_provider.request_redeem(10000, address, vault_provider.get_account_id().clone())
    }))
    .await
    .into_iter()
    .map(|x| x.unwrap())
    .collect::<Vec<_>>();

    // send btc for redeem 0
    btc_rpc
        .send_to_address(
            address,
            10000,
            Some(redeem_ids[0]),
            Duration::from_secs(30),
            0,
        )
        .await
        .unwrap();

    let transaction = btc_rpc
        .create_transaction(address, 10000, Some(redeem_ids[1]))
        .await
        .unwrap()
        .transaction;
    btc_rpc.send_to_mempool(transaction).await;

    join3(
        async {
            vault::service::execute_open_requests(vault_provider, btc_rpc.clone(), 0)
                .await
                .unwrap()
        },
        assert_redeem_event(
            Duration::from_secs(30),
            user_provider.clone(),
            redeem_ids[0],
        ),
        assert_redeem_event(
            Duration::from_secs(30),
            user_provider.clone(),
            redeem_ids[2],
        ),
    )
    .await;

    // now move from mempool into chain and await the remaining redeem
    btc_rpc.flush_mempool().await;
    assert_redeem_event(Duration::from_secs(30), user_provider, redeem_ids[1]).await;
}

async fn assert_redeem_event(
    duration: Duration,
    provider: Arc<PolkaBtcProvider>,
    redeem_id: H256,
) -> ExecuteRedeemEvent<PolkaBtcRuntime> {
    assert_event::<ExecuteRedeemEvent<PolkaBtcRuntime>, _>(duration, provider, |x| {
        x.redeem_id == redeem_id
    })
    .await
}

async fn assert_event<T, F>(duration: Duration, provider: Arc<PolkaBtcProvider>, f: F) -> T
where
    T: Event<PolkaBtcRuntime> + Clone + std::fmt::Debug,
    F: Fn(T) -> bool,
{
    let (tx, mut rx) = futures::channel::mpsc::channel(1);
    warn!("Waiting for event.");
    let event_writer = provider
        .on_event::<T, _, _, _>(
            |event| async {
                warn!("Received event: {:?}", event);
                if (f)(event.clone()) {
                    tx.clone().send(event).await.unwrap();
                }
            },
            |_| {},
        )
        .fuse();
    let event_reader = rx.next().fuse();
    pin_mut!(event_reader, event_writer);

    timeout(duration, async {
        match futures::future::select(event_writer, event_reader).await {
            Either::Right((ret, _)) => ret.unwrap(),
            _ => panic!(),
        }
    })
    .await
    .unwrap()
}
