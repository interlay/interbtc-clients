#![cfg(feature = "testing-utils")]

mod bitcoin_simulator;

use crate::rpc::FeePallet;
use crate::rpc::IssuePallet;
use crate::rpc::VaultRegistryPallet;
use crate::AccountId;
use crate::H256Le;
use crate::PolkaBtcProvider;
use crate::PolkaBtcRuntime;
use bitcoin::BitcoinCoreApi;
use bitcoin::BlockHash;
use bitcoin::Txid;
use futures::{future::Either, pin_mut, Future, FutureExt, SinkExt, StreamExt};
use jsonrpsee::Client as JsonRpseeClient;
use sp_keyring::AccountKeyring;
use sp_runtime::FixedPointNumber;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::Event;
use substrate_subxt::PairSigner;
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;
use tokio::time::timeout;

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
pub async fn default_provider_client(key: AccountKeyring) -> (JsonRpseeClient, TempDir) {
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

/// Create a new provider with the given keyring
pub async fn setup_provider(client: JsonRpseeClient, key: AccountKeyring) -> Arc<PolkaBtcProvider> {
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());
    let mut ret = PolkaBtcProvider::new(client, signer)
        .await
        .expect("Error creating provider");
    ret.relax_storage_finalization_requirement();
    Arc::new(ret)
}

/// request, pay and execute an issue
pub async fn assert_issue(
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
            issue.vault_btc_address,
            issue.amount_btc as u64,
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

/// calculate how much collateral the vault requires to accept an issue of the given size
pub async fn get_required_vault_collateral_for_issue(
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

/// wait for an event to occur. After the specified error, this will panic. This returns the event.
pub async fn assert_event<T, F>(duration: Duration, provider: Arc<PolkaBtcProvider>, f: F) -> T
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
