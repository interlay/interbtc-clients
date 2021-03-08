use sp_runtime::generic::{Block, SignedBlock};
use substrate_subxt::system::System;

use crate::pallets::{
    Core, IssueRequest, RedeemRequest, RefundRequest, ReplaceRequest, RequestIssueEvent,
    RichBlockHeader, StatusUpdate, Vault,
};
use crate::PolkaBtcRuntime;

pub type AccountId = <PolkaBtcRuntime as System>::AccountId;

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

pub type PolkaBtcStatusUpdateId = u64;

pub type PolkaBtcStatusUpdate = StatusUpdate<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as Core>::DOT,
>;

pub type PolkaBtcRichBlockHeader = RichBlockHeader<AccountId>;
