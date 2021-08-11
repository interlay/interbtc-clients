#![cfg(feature = "testing-utils")]

mod bitcoin_simulator;

use crate::{
    rpc::{ExchangeRateOraclePallet, IssuePallet, VaultRegistryPallet},
    AccountId, BtcRelayPallet, H256Le, InterBtcParachain, InterBtcRuntime, OracleKey, DEFAULT_INCLUSION_TIME,
    RELAY_CHAIN_CURRENCY,
};
use bitcoin::{BitcoinCoreApi, BlockHash, Txid};
use frame_support::assert_ok;
use futures::{
    future::{try_join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use sp_keyring::AccountKeyring;
use sp_runtime::FixedU128;
use std::time::Duration;
use substrate_subxt::{Event, PairSigner};
use substrate_subxt_client::{DatabaseConfig, KeystoreConfig, Role, SubxtClientConfig, WasmExecutionMethod};
use tempdir::TempDir;
use tokio::time::{sleep, timeout};

pub use substrate_subxt_client::SubxtClient;

// export the mocked bitcoin interface
pub use bitcoin_simulator::MockBitcoinCore;

/// Trait to help between different types used by the two bitcoin libraries
pub trait Translate {
    type Associated;
    fn translate(&self) -> Self::Associated;
}

impl Translate for Txid {
    type Associated = H256Le;
    fn translate(&self) -> Self::Associated {
        H256Le::from_bytes_le(&self.to_vec())
    }
}

impl Translate for BlockHash {
    type Associated = H256Le;
    fn translate(&self) -> Self::Associated {
        H256Le::from_bytes_le(&self.to_vec())
    }
}

/// Start a new instance of the parachain. The second item in the returned tuple must remain in
/// scope as long as the parachain is active, since dropping it will remove the temporary directory
/// that the parachain uses
pub async fn default_provider_client(key: AccountKeyring) -> (SubxtClient, TempDir) {
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
        chain_spec: interbtc::chain_spec::development_config(),
        role: Role::Authority(key),
        telemetry: None,
        wasm_method: WasmExecutionMethod::Compiled,
    };

    // enable off chain workers
    let mut service_config = config.into_service_config();
    service_config.offchain_worker.enabled = true;

    let (task_manager, rpc_handlers) = interbtc::service::new_full(service_config).unwrap();
    let client = SubxtClient::new(task_manager, rpc_handlers);

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    try_join(
        root_provider.set_bitcoin_confirmations(1),
        root_provider.set_parachain_confirmations(1),
    )
    .await
    .unwrap();

    (client, tmp)
}

/// Create a new parachain_rpc with the given keyring
pub async fn setup_provider(client: SubxtClient, key: AccountKeyring) -> InterBtcParachain {
    let signer = PairSigner::<InterBtcRuntime, _>::new(key.pair());
    InterBtcParachain::new(client, signer)
        .await
        .expect("Error creating parachain_rpc")
}

/// request, pay and execute an issue
pub async fn assert_issue(
    parachain_rpc: &InterBtcParachain,
    btc_rpc: &MockBitcoinCore,
    vault_id: &AccountId,
    amount: u128,
) {
    let issue = parachain_rpc.request_issue(amount, vault_id, 10000).await.unwrap();

    let metadata = btc_rpc
        .send_to_address(issue.vault_btc_address, (issue.amount_btc + issue.fee) as u64, None, 0)
        .await
        .unwrap();

    parachain_rpc
        .execute_issue(issue.issue_id, &metadata.proof, &metadata.raw_tx)
        .await
        .unwrap();
}

const SLEEP_DURATION: Duration = Duration::from_millis(1000);
const TIMEOUT_DURATION: Duration = Duration::from_secs(20);

async fn wait_for_aggregate(parachain_rpc: &InterBtcParachain, key: &OracleKey) {
    while parachain_rpc.has_updated(key).await.unwrap() {
        // should be false upon aggregate update
        sleep(SLEEP_DURATION).await;
    }
}

pub async fn set_exchange_rate(parachain_rpc: &InterBtcParachain, value: FixedU128) {
    assert_ok!(parachain_rpc.set_exchange_rate(value).await);
    assert_ok!(
        timeout(
            TIMEOUT_DURATION,
            wait_for_aggregate(parachain_rpc, &OracleKey::ExchangeRate(RELAY_CHAIN_CURRENCY))
        )
        .await
    );
}

pub async fn set_bitcoin_fees(parachain_rpc: &InterBtcParachain, value: FixedU128) {
    assert_ok!(parachain_rpc.set_bitcoin_fees(value).await);
    assert_ok!(
        timeout(
            TIMEOUT_DURATION,
            wait_for_aggregate(parachain_rpc, &OracleKey::FeeEstimation(DEFAULT_INCLUSION_TIME))
        )
        .await
    );
}

/// calculate how much collateral the vault requires to accept an issue of the given size
pub async fn get_required_vault_collateral_for_issue(parachain_rpc: &InterBtcParachain, amount: u128) -> u128 {
    parachain_rpc.get_required_collateral_for_wrapped(amount).await.unwrap()
}

/// wait for an event to occur. After the specified error, this will panic. This returns the event.
pub async fn assert_event<T, F>(duration: Duration, parachain_rpc: InterBtcParachain, f: F) -> T
where
    T: Event<InterBtcRuntime> + Clone + std::fmt::Debug,
    F: Fn(T) -> bool,
{
    let (tx, mut rx) = futures::channel::mpsc::channel(1);
    let event_writer = parachain_rpc
        .on_event::<T, _, _, _>(
            |event| async {
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
    .unwrap_or_else(|_| panic!("could not find event: {}::{}", T::MODULE, T::EVENT))
}

/// run `service` in the background, and run `fut`. If the service completes before the
/// second future, this will panic
pub async fn test_service<T: Future, U: Future>(service: T, fut: U) -> U::Output {
    pin_mut!(service, fut);
    match futures::future::select(service, fut).await {
        Either::Right((ret, _)) => ret,
        _ => panic!(),
    }
}
