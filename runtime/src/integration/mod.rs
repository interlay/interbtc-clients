#![cfg(feature = "testing-utils")]

mod bitcoin_simulator;

use crate::{
    rpc::{IssuePallet, OraclePallet, SudoPallet, VaultRegistryPallet},
    CurrencyId, FixedU128, H256Le, InterBtcParachain, InterBtcSigner, OracleKey, PartialAddress, VaultId,
};
use bitcoin::{BitcoinCoreApi, BlockHash, SatPerVbyte, Txid};
use frame_support::assert_ok;
use futures::{
    future::{try_join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use std::{sync::Arc, time::Duration};
use subxt::Event;
use subxt_client::{
    AccountKeyring, DatabaseSource, KeystoreConfig, Role, SubxtClientConfig, WasmExecutionMethod,
    WasmtimeInstantiationStrategy,
};
use tempdir::TempDir;
use tokio::time::{sleep, timeout};

type DynBitcoinCoreApi = Arc<dyn BitcoinCoreApi + Send + Sync>;

pub use subxt_client::SubxtClient;

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
        H256Le::from_bytes_le(self)
    }
}

impl Translate for BlockHash {
    type Associated = H256Le;
    fn translate(&self) -> Self::Associated {
        H256Le::from_bytes_le(self)
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
        db: DatabaseSource::ParityDb {
            path: tmp.path().join("db"),
        },
        keystore: KeystoreConfig::Path {
            path: tmp.path().join("keystore"),
            password: None,
        },
        chain_spec: interbtc::chain_spec::testnet_kintsugi::development_config(2121u32.into()),
        role: Role::Authority(key),
        telemetry: None,
        wasm_method: WasmExecutionMethod::Compiled {
            instantiation_strategy: WasmtimeInstantiationStrategy::LegacyInstanceReuse,
        },
        tokio_handle: tokio::runtime::Handle::current(),
    };

    // enable off chain workers
    let mut service_config = config.into_service_config();
    service_config.offchain_worker.enabled = true;

    let (task_manager, rpc_handlers) = interbtc::service::start_instant::<
        interbtc_runtime::RuntimeApi,
        interbtc::service::TestnetKintsugiRuntimeExecutor,
    >(service_config)
    .await
    .unwrap();

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
    let signer = InterBtcSigner::new(key.pair());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

    InterBtcParachain::new(client, signer, shutdown_tx)
        .await
        .expect("Error creating parachain_rpc")
}

/// request, pay and execute an issue
pub async fn assert_issue(
    parachain_rpc: &InterBtcParachain,
    btc_rpc: &DynBitcoinCoreApi,
    vault_id: &VaultId,
    amount: u128,
) {
    let issue = parachain_rpc.request_issue(amount, vault_id).await.unwrap();

    let fee_rate = SatPerVbyte(1000);

    let metadata = btc_rpc
        .send_to_address(
            issue.vault_address.to_address(btc_rpc.network()).unwrap(),
            (issue.amount + issue.fee) as u64,
            None,
            fee_rate,
            0,
        )
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

pub async fn set_exchange_rate_and_wait(parachain_rpc: &InterBtcParachain, currency_id: CurrencyId, value: FixedU128) {
    let key = OracleKey::ExchangeRate(currency_id);
    assert_ok!(parachain_rpc.feed_values(vec![(key.clone(), value)]).await);
    parachain_rpc.manual_seal().await; // we need a new block to get on_initialize to run
    assert_ok!(timeout(TIMEOUT_DURATION, wait_for_aggregate(parachain_rpc, &key)).await);
}

pub async fn set_bitcoin_fees(parachain_rpc: &InterBtcParachain, value: FixedU128) {
    assert_ok!(parachain_rpc.set_bitcoin_fees(value).await);
    parachain_rpc.manual_seal().await; // we need a new block to get on_initialize to run
    assert_ok!(
        timeout(
            TIMEOUT_DURATION,
            wait_for_aggregate(parachain_rpc, &OracleKey::FeeEstimation)
        )
        .await
    );
}

/// calculate how much collateral the vault requires to accept an issue of the given size
pub async fn get_required_vault_collateral_for_issue(
    parachain_rpc: &InterBtcParachain,
    amount: u128,
    collateral_currency: CurrencyId,
) -> u128 {
    parachain_rpc
        .get_required_collateral_for_wrapped(amount, collateral_currency)
        .await
        .unwrap()
}

/// wait for an event to occur. After the specified error, this will panic. This returns the event.
pub async fn assert_event<T, F>(duration: Duration, parachain_rpc: InterBtcParachain, f: F) -> T
where
    T: Event + Clone + std::fmt::Debug,
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
    .unwrap_or_else(|_| panic!("could not find event: {}::{}", T::PALLET, T::EVENT))
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

pub async fn with_timeout<T: Future>(future: T, duration: Duration) -> T::Output {
    timeout(duration, future).await.expect("timeout")
}

pub async fn periodically_produce_blocks(parachain_rpc: InterBtcParachain) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        parachain_rpc.manual_seal().await;
    }
}
