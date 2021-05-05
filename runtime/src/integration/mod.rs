#![cfg(feature = "testing-utils")]

mod bitcoin_simulator;

use crate::{
    rpc::{IssuePallet, VaultRegistryPallet},
    AccountId, BtcRelayPallet, H256Le, PolkaBtcProvider, PolkaBtcRuntime,
};
use bitcoin::{BitcoinCoreApi, BlockHash, Txid};
use futures::{
    future::{try_join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use sp_keyring::AccountKeyring;
use std::time::Duration;
use substrate_subxt::{Event, PairSigner};
use substrate_subxt_client::{DatabaseConfig, KeystoreConfig, Role, SubxtClientConfig, WasmExecutionMethod};
use tempdir::TempDir;
use tokio::time::timeout;

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
        chain_spec: btc_parachain::chain_spec::development_config(),
        role: Role::Authority(key),
        telemetry: None,
        wasm_method: WasmExecutionMethod::Compiled,
    };

    // enable off chain workers
    let mut service_config = config.into_service_config();
    service_config.offchain_worker.enabled = true;

    let (task_manager, rpc_handlers) = btc_parachain_service::new_full(service_config).unwrap();
    let client = SubxtClient::new(task_manager, rpc_handlers);

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    try_join(
        root_provider.set_bitcoin_confirmations(1),
        root_provider.set_parachain_confirmations(1),
    )
    .await
    .unwrap();

    return (client, tmp);
}

/// Create a new provider with the given keyring
pub async fn setup_provider(client: SubxtClient, key: AccountKeyring) -> PolkaBtcProvider {
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());
    PolkaBtcProvider::new(client, signer)
        .await
        .expect("Error creating provider")
}

/// request, pay and execute an issue
pub async fn assert_issue(provider: &PolkaBtcProvider, btc_rpc: &MockBitcoinCore, vault_id: &AccountId, amount: u128) {
    let issue = provider.request_issue(amount, vault_id.clone(), 10000).await.unwrap();

    let metadata = btc_rpc
        .send_to_address(
            issue.vault_btc_address,
            (issue.amount_btc + issue.fee) as u64,
            None,
            Duration::from_secs(30),
            0,
        )
        .await
        .unwrap();

    provider
        .execute_issue(issue.issue_id, metadata.proof, metadata.raw_tx)
        .await
        .unwrap();
}

/// calculate how much collateral the vault requires to accept an issue of the given size
pub async fn get_required_vault_collateral_for_issue(provider: &PolkaBtcProvider, amount: u128) -> u128 {
    provider.get_required_collateral_for_issuing(amount).await.unwrap()
}

/// wait for an event to occur. After the specified error, this will panic. This returns the event.
pub async fn assert_event<T, F>(duration: Duration, provider: PolkaBtcProvider, f: F) -> T
where
    T: Event<PolkaBtcRuntime> + Clone + std::fmt::Debug,
    F: Fn(T) -> bool,
{
    let (tx, mut rx) = futures::channel::mpsc::channel(1);
    let event_writer = provider
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
    .unwrap()
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
