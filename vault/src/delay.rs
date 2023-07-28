use async_trait::async_trait;
use bitcoin::{sha256, Hash};
use runtime::{AccountId, Error as RuntimeError, InterBtcParachain, UtilFuncs, VaultRegistryPallet};
use std::fmt;

#[async_trait]
pub trait RandomDelay: fmt::Debug {
    async fn delay(&self, seed_data: &[u8; 32]) -> Result<(), RuntimeError>;
}

#[derive(Clone)]
pub struct OrderedVaultsDelay {
    btc_parachain: InterBtcParachain,
    /// Order relative to this set of vaults
    vaults: Vec<AccountId>,
}

impl OrderedVaultsDelay {
    pub async fn new(btc_parachain: InterBtcParachain) -> Result<Self, RuntimeError> {
        let vaults = btc_parachain
            .get_all_vaults()
            .await?
            .into_iter()
            .map(|vault| vault.id.account_id)
            .collect();
        Ok(Self { btc_parachain, vaults })
    }
}

impl fmt::Debug for OrderedVaultsDelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedDelayableVaults")
            .field("btc_parachain", &self.btc_parachain.get_account_id())
            .field("vaults", &self.vaults)
            .finish()
    }
}

#[async_trait]
impl RandomDelay for OrderedVaultsDelay {
    /// Calculates a delay based on randomly ordering the vaults by hashing their
    /// account ID with a piece of seed data.
    /// Then awaits a corresponding amount of blocks on the parachain, with
    /// logarithmic falloff. E.g. first vault in the ordering waits 0 blocks,
    /// vaults 2-3 wait 1 block, vaults 4-7 wait 2 blocks, 8-15 wait 3 blocks etc.
    ///
    /// # Arguments
    /// * `data` - the seed used as a basis for the ordering (for example, an issue_id)
    async fn delay(&self, seed_data: &[u8; 32]) -> Result<(), RuntimeError> {
        fn hash_vault(data: &[u8; 32], account_id: &AccountId) -> sha256::Hash {
            let account_id = account_id.0.clone();
            let account_id: [u8; 32] = (*account_id).clone().into();
            let xor = data.zip(account_id).map(|(a, b)| a ^ b);
            sha256::Hash::hash(&xor)
        }

        let self_hash = hash_vault(seed_data, self.btc_parachain.get_account_id());

        let random_ordering = self
            .vaults
            .iter()
            .filter(|account_id| hash_vault(seed_data, account_id) < self_hash)
            .count();
        let delay: u32 = (random_ordering + 1).ilog2();
        self.btc_parachain.delay_for_blocks(delay).await
    }
}

#[derive(Clone, Debug)]
pub struct ZeroDelay;

#[async_trait]
impl RandomDelay for ZeroDelay {
    async fn delay(&self, _seed_data: &[u8; 32]) -> Result<(), RuntimeError> {
        Ok(())
    }
}
