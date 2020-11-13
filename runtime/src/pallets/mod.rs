pub mod balances_dot;
pub mod btc_relay;
pub mod collateral;
pub mod exchange_rate_oracle;
pub mod issue;
pub mod redeem;
pub mod replace;
pub mod security;
pub mod staked_relayers;
pub mod timestamp;
pub mod vault_registry;

pub use btc_relay::{BitcoinBlockHeight, H256Le, RawBlockHeader, RichBlockHeader};
pub use security::{ErrorCode, StatusCode};

use parity_scale_codec::{Codec, EncodeLike};
use sp_runtime::traits::Member;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::module;

#[module]
pub trait Core: System {
    #[allow(non_camel_case_types)]
    type u64: Codec + EncodeLike + Member + Default;
    #[allow(non_camel_case_types)]
    type u128: Codec + EncodeLike + Member + Default;

    type DOT: Codec + EncodeLike + Member + Default;
    type Balance: Codec + EncodeLike + Member + Default;
    type BTCBalance: Codec + EncodeLike + Member + Default;
    type PolkaBTC: Codec + EncodeLike + Member + Default;
    type RichBlockHeader: Codec + EncodeLike + Member + Default;
    type H256Le: Codec + EncodeLike + Member + Default;
    type H256: Codec + EncodeLike + Member + Default;
    type H160: Codec + EncodeLike + Member + Default;

    type ErrorCodes: Codec + EncodeLike + Member + Default;
    type ErrorCode: Codec + EncodeLike + Member + Default;
    type StatusCode: Codec + EncodeLike + Member + Default;
}
