use runtime::{AccountId, BtcAddress, PolkaBtcVault};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct Vaults(RwLock<HashMap<BtcAddress, AccountId>>);

impl Vaults {
    pub async fn write(&self, key: BtcAddress, value: AccountId) {
        self.0.write().await.insert(key, value);
    }

    pub async fn add_vault(&self, vault: PolkaBtcVault) {
        let mut vaults = self.0.write().await;
        for address in vault.wallet.addresses {
            vaults.insert(address, vault.id.clone());
        }
    }

    pub async fn contains_key(&self, key: BtcAddress) -> Option<AccountId> {
        let vaults = self.0.read().await;
        vaults.get(&key).map(|id| id.clone())
    }
}

impl From<HashMap<BtcAddress, AccountId>> for Vaults {
    fn from(vaults: HashMap<BtcAddress, AccountId>) -> Self {
        Self(RwLock::new(vaults))
    }
}
