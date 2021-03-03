pub mod balances_dot;
pub mod btc_relay;
pub mod collateral;
pub mod exchange_rate_oracle;
pub mod fee;
pub mod frame_system;
pub mod issue;
pub mod redeem;
pub mod refund;
pub mod replace;
pub mod security;
pub mod sla;
pub mod staked_relayers;
pub mod timestamp;
pub mod treasury;
pub mod vault_registry;

pub use btc_relay::{
    BitcoinBlockHeight, BtcAddress, BtcPublicKey, H256Le, RawBlockHeader, RichBlockHeader,
};
pub use issue::{IssueRequest, RequestIssueEvent};
pub use redeem::RedeemRequest;
pub use refund::RefundRequest;
pub use replace::ReplaceRequest;
pub use security::{ErrorCode, StatusCode};
pub use staked_relayers::StatusUpdate;
pub use vault_registry::Vault;

use parity_scale_codec::{Codec, EncodeLike};
use sp_arithmetic::traits::Saturating;
use sp_runtime::traits::Member;
use substrate_subxt::system::System;
use substrate_subxt_proc_macro::module;

#[module]
pub trait Core: System {
    type DOT: Codec + EncodeLike + Member + Default + PartialOrd + Saturating;
    type Balance: Codec + EncodeLike + Member + Default;
    type BTCBalance: Codec + EncodeLike + Member + Default;
    type PolkaBTC: Codec + EncodeLike + Member + Default;
    type RichBlockHeader: Codec + EncodeLike + Member + Default;
    type H256Le: Codec + EncodeLike + Member + Default;
    type H256: Codec + EncodeLike + Member + Default;
    type H160: Codec + EncodeLike + Member + Default;
    type BtcAddress: Codec + EncodeLike + Member + Default;
    type BtcPublicKey: Codec + EncodeLike + Member + Default;
    type ErrorCodes: Codec + EncodeLike + Member + Default;
    type ErrorCode: Codec + EncodeLike + Member + Default;
    type StatusCode: Codec + EncodeLike + Member + Default;
    type StatusUpdateId: Codec + EncodeLike + Member + Default;
    type SignedFixedPoint: Codec + EncodeLike + Member + Default;
    type UnsignedFixedPoint: Codec + EncodeLike + Member + Default;
    type VaultStatus: Codec + EncodeLike + Default + Send + Sync;

    // cumulus / polkadot types
    type XcmError: Codec + EncodeLike + Member;
    type NetworkId: Codec + EncodeLike + Member;
    type RelayChainBlockNumber: Codec + EncodeLike + Member + Default;
    type ParaId: Codec + EncodeLike + Member + Default;
}
