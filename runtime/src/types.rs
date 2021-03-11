use sp_core::sr25519::Pair as KeyPair;
use sp_runtime::generic::{Block, SignedBlock};
use substrate_subxt::{system::System, PairSigner, Signer};
use tokio::sync::RwLock;

use crate::pallets::{
    Core, IssueRequest, RedeemRequest, RefundRequest, ReplaceRequest, RequestIssueEvent,
    RichBlockHeader, StatusUpdate, Vault,
};
use crate::PolkaBtcRuntime;

pub type AccountId = <PolkaBtcRuntime as System>::AccountId;

pub type Index = <PolkaBtcRuntime as System>::Index;

pub type PolkaBtcHeader = <PolkaBtcRuntime as System>::Header;

pub type PolkaBtcBlock = SignedBlock<Block<PolkaBtcHeader, <PolkaBtcRuntime as System>::Extrinsic>>;

pub type PolkaBtcVault = Vault<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as Core>::PolkaBTC,
    <PolkaBtcRuntime as Core>::DOT,
>;

pub type PolkaBtcIssueRequest = IssueRequest<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as Core>::PolkaBTC,
    <PolkaBtcRuntime as Core>::DOT,
>;

pub type PolkaBtcRequestIssueEvent = RequestIssueEvent<PolkaBtcRuntime>;

pub type PolkaBtcRedeemRequest = RedeemRequest<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as Core>::PolkaBTC,
    <PolkaBtcRuntime as Core>::DOT,
>;

pub type PolkaBtcRefundRequest = RefundRequest<AccountId, <PolkaBtcRuntime as Core>::PolkaBTC>;

pub type PolkaBtcReplaceRequest = ReplaceRequest<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as Core>::PolkaBTC,
    <PolkaBtcRuntime as Core>::DOT,
>;

pub type PolkaBtcStatusUpdate = StatusUpdate<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as Core>::DOT,
>;

pub type PolkaBtcRichBlockHeader = RichBlockHeader<AccountId>;

pub struct PolkaBtcSigner(pub(crate) RwLock<PairSigner<PolkaBtcRuntime, KeyPair>>);

impl PolkaBtcSigner {
    pub async fn account_id(&self) -> AccountId {
        self.0.read().await.account_id().clone()
    }

    pub(crate) async fn set_nonce(&self, nonce: Index) {
        self.0.write().await.set_nonce(nonce);
    }
}

impl From<PairSigner<PolkaBtcRuntime, KeyPair>> for PolkaBtcSigner {
    fn from(signer: PairSigner<PolkaBtcRuntime, KeyPair>) -> Self {
        Self(RwLock::new(signer))
    }
}
