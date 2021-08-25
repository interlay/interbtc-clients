use sp_core::sr25519::Pair as KeyPair;
use sp_runtime::generic::{Block, SignedBlock};
use substrate_subxt::{system::System, PairSigner};

use crate::{
    pallets::{
        issue::RequestIssueEvent, Core, IssueRequest, RedeemRequest, RefundRequest, ReplaceRequest, RichBlockHeader,
        Vault,
    },
    CurrencyId, InterBtcRuntime,
};

type AccountId = <InterBtcRuntime as System>::AccountId;

type BlockNumber = <InterBtcRuntime as System>::BlockNumber;

pub type InterBtcHeader = <InterBtcRuntime as System>::Header;

pub type InterBtcBalance = <InterBtcRuntime as Core>::Balance;

pub type InterBtcBlock = SignedBlock<Block<InterBtcHeader, <InterBtcRuntime as System>::Extrinsic>>;

pub type InterBtcVault = Vault<AccountId, BlockNumber, InterBtcBalance, CurrencyId>;

pub type InterBtcIssueRequest = IssueRequest<AccountId, BlockNumber, InterBtcBalance>;

pub type InterBtcRequestIssueEvent = RequestIssueEvent<InterBtcRuntime>;

pub type InterBtcRedeemRequest = RedeemRequest<AccountId, BlockNumber, InterBtcBalance>;

pub type InterBtcRefundRequest = RefundRequest<AccountId, <InterBtcRuntime as Core>::Wrapped>;

pub type InterBtcReplaceRequest = ReplaceRequest<AccountId, BlockNumber, InterBtcBalance>;

pub type InterBtcRichBlockHeader = RichBlockHeader<BlockNumber>;

pub type InterBtcSigner = PairSigner<InterBtcRuntime, KeyPair>;
