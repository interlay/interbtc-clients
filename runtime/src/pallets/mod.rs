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
pub mod utility;
pub mod vault_registry;

pub use module_bitcoin::{formatter::Formattable, types::*};
pub use module_btc_relay::{BtcAddress, BtcPublicKey, RichBlockHeader};
pub use module_issue::{IssueRequest, IssueRequestStatus};
pub use module_redeem::{RedeemRequest, RedeemRequestStatus};
pub use module_refund::RefundRequest;
pub use module_replace::{ReplaceRequest, ReplaceRequestStatus};
pub use module_security::{ErrorCode, StatusCode};
pub use module_staked_relayers::{
    types::{StakedRelayer, StatusUpdate},
    Error as StakedRelayersError,
};
pub use module_vault_registry::{Vault, VaultStatus};

pub use sp_core::{H160, H256, U256};

use codec::{Codec, EncodeLike};
use sp_arithmetic::traits::Saturating;
use sp_runtime::traits::{AtLeast32Bit, Member};
use substrate_subxt::system::System;
use substrate_subxt_proc_macro::module;

pub type BitcoinBlockHeight = u32;

#[module]
pub trait Core: System {
    type DOT: Codec + EncodeLike + Member + Default + PartialOrd + Saturating + AtLeast32Bit;
    type Balance: Codec + EncodeLike + Member + Default;
    type BTCBalance: Codec + EncodeLike + Member + Default;
    type PolkaBTC: Codec + EncodeLike + Member + Default + AtLeast32Bit;
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
