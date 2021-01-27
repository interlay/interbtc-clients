#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

mod bitcoin_simulator;
use bitcoin_simulator::*;

use bitcoin::{
    key,
    secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey},
    serialize, Address, BitcoinCore, BitcoinCoreApi, Block, BlockHash, BlockHeader,
    Error as BitcoinError, GetBlockResult, Hash, LockedTransaction, Network, OutPoint,
    PartialAddress, PartialMerkleTree, Script, Transaction, TransactionMetadata, TxIn,
    TxMerkleNode, TxOut, Txid, Uint256, PUBLIC_KEY_SIZE,
};
use runtime::pallets::{
    btc_relay::{TransactionBuilder, TransactionInputBuilder, TransactionOutput},
    replace::AcceptReplaceCall,
};
use runtime::BtcAddress::P2PKH;
use runtime::UtilFuncs;
use runtime::{
    pallets::issue::*,
    pallets::redeem::*,
    pallets::refund::*,
    pallets::replace::*,
    pallets::treasury::*,
    substrate_subxt::{Event, PairSigner},
    BlockBuilder, BtcAddress, BtcPublicKey, BtcRelayPallet, ExchangeRateOraclePallet, FeePallet,
    FixedPointNumber, FixedU128, Formattable, H256Le, IssuePallet, PolkaBtcProvider,
    PolkaBtcRuntime, RawBlockHeader, RedeemPallet, ReplacePallet, VaultRegistryPallet,
};
use sp_core::H160;
use sp_core::H256;
use sp_core::U256;
use sp_keyring::AccountKeyring;
// use staked_relayer;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::Either;
use futures::future::{join, try_join};
use futures::pin_mut;
use futures::Future;
use futures::FutureExt;
use futures::SinkExt;
use futures::StreamExt;
use jsonrpsee::Client as JsonRpseeClient;
use log::*;
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tokio::time::delay_for;
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

fn default_vault_args() -> vault::Opts {
    vault::Opts {
        polka_btc_url: "".to_string(), // only used by bin
        http_addr: "".to_string(),     // only used by bin
        rpc_cors_domain: "*".to_string(),
        auto_register_with_collateral: Some(50000000),
        no_auto_auction: false,
        no_auto_replace: false,
        no_startup_collateral_increase: false,
        max_collateral: 50000000,
        collateral_timeout_ms: 1000,
        no_api: true,
        account_info: runtime::cli::ProviderUserOpts {
            keyname: None,
            keyfile: None,
            keyring: Some(AccountKeyring::Bob),
        },
        btc_confirmations: None,
        no_issue_execution: false,
        bitcoin: bitcoin::cli::BitcoinOpts {
            bitcoin_rpc_url: "http://localhost:18443".to_string(),
            bitcoin_rpc_user: "rpcuser".to_string(),
            bitcoin_rpc_pass: "rpcpassword".to_string(),
        },
        network: vault::BitcoinNetwork::from_str("regtest").unwrap(),
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
        chain_spec: btc_parachain::chain_spec::development_config(21u32.into()),
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

    vault_provider
        .register_vault(100000000000, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let issue = user_provider
        .request_issue(100000, vault_provider.get_account_id().clone(), 10000)
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

    user_provider
        .execute_issue(
            issue.issue_id,
            metadata.txid.translate(),
            metadata.proof,
            metadata.raw_tx,
        )
        .await
        .unwrap();

    let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
    let vault_id = vault_provider.get_account_id().clone();
    let fut = test_service(
        vault::service::listen_for_redeem_requests(vault_provider, btc_rpc, 0),
        async {
            let redeem_id = user_provider
                .request_redeem(10000, address, vault_id)
                .await
                .unwrap();
            assert_redeem_event(Duration::from_secs(30), user_provider, redeem_id).await;
        },
    );
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

    old_vault_provider
        .register_vault(100000000000, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    new_vault_provider
        .register_vault(100000000000, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let issue_amount = 100000;
    let issue = user_provider
        .request_issue(100000, old_vault_provider.get_account_id().clone(), 10000)
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

    user_provider
        .execute_issue(
            issue.issue_id,
            metadata.txid.translate(),
            metadata.proof,
            metadata.raw_tx,
        )
        .await
        .unwrap();

    let (replace_event_tx, _) = mpsc::channel::<RequestEvent>(16);
    let fut = test_service(
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
    let fee = user_provider.get_issue_fee().await.unwrap();
    let amount_btc_including_fee = issue_amount + fee.checked_mul_int(issue_amount).unwrap();
    let collateral = user_provider
        .get_required_collateral_for_polkabtc(amount_btc_including_fee)
        .await
        .unwrap();

    old_vault_provider
        .register_vault(collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    new_vault_provider
        .register_vault(collateral * 2, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let issue = user_provider
        .request_issue(
            issue_amount,
            old_vault_provider.get_account_id().clone(),
            10000,
        )
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

    user_provider
        .execute_issue(
            issue.issue_id,
            metadata.txid.translate(),
            metadata.proof,
            metadata.raw_tx,
        )
        .await
        .unwrap();

    let (replace_event_tx, _) = mpsc::channel::<RequestEvent>(16);
    let fut = test_service(
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
    let fee = user_provider.get_issue_fee().await.unwrap();
    let amount_btc_including_fee = issue_amount + fee.checked_mul_int(issue_amount).unwrap();
    let collateral = user_provider
        .get_required_collateral_for_polkabtc(amount_btc_including_fee)
        .await
        .unwrap();

    vault_provider
        .register_vault(collateral, btc_rpc.get_new_public_key().await.unwrap())
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
    let total_btc = issue_amount * over_payment_factor;
    let fee = user_provider.get_issue_fee().await.unwrap();
    let amount_btc_including_fee = total_btc + fee.checked_mul_int(total_btc).unwrap();
    let collateral = user_provider
        .get_required_collateral_for_polkabtc(amount_btc_including_fee)
        .await
        .unwrap();

    vault_provider
        .register_vault(collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let vault_id = vault_provider.get_account_id().clone();
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

        let (refund_request, _) = join(
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
    let fee = user_provider.get_issue_fee().await.unwrap();
    let amount_btc_including_fee = issue_amount + fee.checked_mul_int(issue_amount).unwrap();
    let collateral = user_provider
        .get_required_collateral_for_polkabtc(amount_btc_including_fee)
        .await
        .unwrap();

    vault1_provider
        .register_vault(collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();
    vault2_provider
        .register_vault(collateral, btc_rpc.get_new_public_key().await.unwrap())
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
    let (issue_event_tx, issue_event_rx) = mpsc::channel::<RequestEvent>(16);
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

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100))
        .await
        .unwrap();

    vault_provider
        .register_vault(100000000000, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let issue = user_provider
        .request_issue(100000, vault_provider.get_account_id().clone(), 10000)
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

    user_provider
        .execute_issue(
            issue.issue_id,
            metadata.txid.translate(),
            metadata.proof,
            metadata.raw_tx,
        )
        .await
        .unwrap();

    let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
    let redeem_id = user_provider
        .request_redeem(10000, address, vault_provider.get_account_id().clone())
        .await
        .unwrap();

    let ret = join(
        vault::service::execute_open_requests(vault_provider, Arc::new(btc_rpc), 0),
        assert_redeem_event(Duration::from_secs(30), user_provider, redeem_id),
    )
    .await;
    ret.0.unwrap();
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
