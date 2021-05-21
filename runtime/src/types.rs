use sp_core::sr25519::Pair as KeyPair;
use sp_runtime::generic::{Block, SignedBlock};
use substrate_subxt::{system::System, PairSigner};

use crate::{
    pallets::{
        issue::RequestIssueEvent, Core, IssueRequest, RedeemRequest, RefundRequest, ReplaceRequest, RichBlockHeader,
        Vault,
    },
    PolkaBtcRuntime,
};

type AccountId = <PolkaBtcRuntime as System>::AccountId;

type BlockNumber = <PolkaBtcRuntime as System>::BlockNumber;

pub type PolkaBtcHeader = <PolkaBtcRuntime as System>::Header;

pub type PolkaBtcBalance = <PolkaBtcRuntime as Core>::Balance;

pub type PolkaBtcBlock = SignedBlock<Block<PolkaBtcHeader, <PolkaBtcRuntime as System>::Extrinsic>>;

pub type PolkaBtcVault = Vault<
    AccountId,
    BlockNumber,
    <PolkaBtcRuntime as Core>::Wrapped,
    <PolkaBtcRuntime as Core>::Collateral,
    <PolkaBtcRuntime as Core>::SignedFixedPoint,
>;

pub type PolkaBtcIssueRequest =
    IssueRequest<AccountId, BlockNumber, <PolkaBtcRuntime as Core>::Wrapped, <PolkaBtcRuntime as Core>::Collateral>;

pub type PolkaBtcRequestIssueEvent = RequestIssueEvent<PolkaBtcRuntime>;

pub type PolkaBtcRedeemRequest =
    RedeemRequest<AccountId, BlockNumber, <PolkaBtcRuntime as Core>::Wrapped, <PolkaBtcRuntime as Core>::Collateral>;

pub type PolkaBtcRefundRequest = RefundRequest<AccountId, <PolkaBtcRuntime as Core>::Wrapped>;

pub type PolkaBtcReplaceRequest =
    ReplaceRequest<AccountId, BlockNumber, <PolkaBtcRuntime as Core>::Wrapped, <PolkaBtcRuntime as Core>::Collateral>;

pub type PolkaBtcRichBlockHeader = RichBlockHeader<AccountId, BlockNumber>;

pub type PolkaBtcSigner = PairSigner<PolkaBtcRuntime, KeyPair>;
