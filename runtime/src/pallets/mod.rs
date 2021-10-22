pub mod btc_relay;
pub mod exchange_rate_oracle;
pub mod fee;
pub mod frame_system;
pub mod issue;
pub mod redeem;
pub mod refund;
pub mod relay;
pub mod replace;
pub mod security;
pub mod sla;
pub mod timestamp;
pub mod tokens;
pub mod utility;
pub mod vault_registry;

pub use module_bitcoin::{formatter::Formattable, types::*};
pub use module_btc_relay::{BtcAddress, BtcPublicKey, RichBlockHeader, MAIN_CHAIN_ID};
pub use module_security::{ErrorCode, StatusCode};
pub use module_vault_registry::{Vault, VaultStatus, Wallet};
pub use primitives::{
    issue::{IssueRequest, IssueRequestStatus},
    redeem::{RedeemRequest, RedeemRequestStatus},
    refund::RefundRequest,
    replace::{ReplaceRequest, ReplaceRequestStatus},
};

use serde::Serialize;
pub use sp_core::{H160, H256, U256};

use codec::{Codec, EncodeLike};
use frame_support::Parameter;
use sp_arithmetic::traits::Saturating;
use sp_runtime::traits::{AtLeast32Bit, Member};
use substrate_subxt::system::System;
use substrate_subxt_proc_macro::module;

pub type BitcoinBlockHeight = u32;

#[module]
pub trait Core: System {
    type Collateral: Codec + EncodeLike + Member + Default + PartialOrd + Saturating + AtLeast32Bit;
    type Wrapped: Codec + EncodeLike + Member + Default + AtLeast32Bit;
    type Balance: Parameter + AtLeast32Bit + Codec + EncodeLike + Member + Default;
    type RichBlockHeader: Codec + EncodeLike + Member + Default;
    type H256Le: Codec + EncodeLike + Member + Default;
    type H256: Codec + EncodeLike + Member + Default;
    type H160: Codec + EncodeLike + Member + Default;
    type BtcAddress: Codec + EncodeLike + Member + Default;
    type BtcPublicKey: Codec + EncodeLike + Member + Default;
    type ErrorCodeSet: Codec + EncodeLike + Member + Default;
    type ErrorCode: Codec + EncodeLike + Member + Default;
    type StatusCode: Codec + EncodeLike + Member + Default;
    type SignedFixedPoint: Codec + EncodeLike + Member + Default;
    type UnsignedFixedPoint: Codec + EncodeLike + Member + Default;
    type VaultStatus: Codec + EncodeLike + Default + Send + Sync;
    type RedeemRequestStatus: Codec + EncodeLike + Default + Send + Sync;
    type CurrencyId: Codec + EncodeLike + Send + Sync + Copy + Serialize;
    type OracleKey: Codec + EncodeLike + Send + Sync;
    type VaultId: Codec + EncodeLike + Member;

    // cumulus / polkadot types
    type XcmError: Codec + EncodeLike + Member;
    type NetworkId: Codec + EncodeLike + Member;
    type RelayChainBlockNumber: Codec + EncodeLike + Member + Default;
    type ParaId: Codec + EncodeLike + Member + Default;
}
