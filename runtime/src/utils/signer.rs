//! A signer suitable for substrate based chains. This provides compatibility with Substrate
//! packages like sp_keyring and such, and so relies on sp_core and sp_runtime to be included.
//! Custom implementation needed because as it feature gated by subxt `substrate-compat` feature
//! flag.
use crate::Config;
use sp_core::Pair as PairT;
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    AccountId32 as SpAccountId32, MultiSignature as SpMultiSignature,
};

use subxt::tx::Signer;

/// A [`Signer`] implementation that can be constructed from an [`sp_core::Pair`].
#[derive(Clone, Debug)]
pub struct PairSigner<T: Config, Pair> {
    account_id: T::AccountId,
    pub signer: Pair,
}

impl<T, Pair> PairSigner<T, Pair>
where
    T: Config,
    Pair: PairT,
    // We go via an sp_runtime::MultiSignature. We can probably generalise this
    // by implementing some of these traits on our built-in MultiSignature and then
    // requiring them on all T::Signatures, to avoid any go-between.
    <SpMultiSignature as Verify>::Signer: From<Pair::Public>,
    T::AccountId: From<SpAccountId32>,
{
    /// Creates a new [`Signer`] from an [`sp_core::Pair`].
    pub fn new(signer: Pair) -> Self
    where
        <T as subxt::Config>::AccountId: From<sp_runtime::AccountId32>,
    {
        let account_id = <SpMultiSignature as Verify>::Signer::from(signer.public()).into_account();
        Self {
            account_id: account_id.into(),
            signer,
        }
    }

    /// Returns the [`sp_core::Pair`] implementation used to construct this.
    pub fn signer(&self) -> &Pair {
        &self.signer
    }

    /// Return the account ID.
    pub fn account_id(&self) -> &T::AccountId {
        &self.account_id
    }
}

impl<T, Pair> Signer<T> for PairSigner<T, Pair>
where
    T: Config,
    Pair: PairT,
    Pair::Signature: Into<T::Signature>,
{
    fn account_id(&self) -> &T::AccountId {
        &self.account_id
    }

    fn address(&self) -> T::Address {
        self.account_id.clone().into()
    }

    fn sign(&self, signer_payload: &[u8]) -> T::Signature {
        self.signer.sign(signer_payload).into()
    }
}
