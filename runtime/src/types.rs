use crate::{
    metadata,
    utils::{account_id::AccountId32, signer::PairSigner},
    Config, InterBtcRuntime, RuntimeCurrencyInfo, SS58_PREFIX,
};
pub use currency_id::CurrencyIdExt;
pub use h256_le::RichH256Le;
pub use metadata_aliases::*;
pub use primitives::{
    CurrencyId,
    CurrencyId::{ForeignAsset, LendToken, Token},
    TokenSymbol::{self, DOT, IBTC, INTR, KBTC, KINT, KSM},
};
pub use sp_core::sr25519::Pair as KeyPair;
pub use subxt;
use subxt::storage::{address::Yes, Address};

pub type AccountId = AccountId32;
pub type MultiSignature = sp_runtime::MultiSignature;
pub type Balance = primitives::Balance;
pub type Index = u32;
pub type BlockNumber = u32;
pub type H160 = sp_core::H160;
pub type H256 = sp_core::H256;
pub type U256 = sp_core::U256;
pub type Ratio = sp_runtime::Permill;

pub type InterBtcSigner = PairSigner<InterBtcRuntime, KeyPair>;

pub type BtcAddress = module_bitcoin::Address;
pub type FixedU128 = crate::FixedU128;
#[allow(non_camel_case_types)]
pub(crate) enum StorageMapHasher {
    Blake2_128,
    Twox_64,
}

mod metadata_aliases {
    use super::*;
    use subxt::{storage::address::StaticStorageMapKey, utils::Static};

    // AssetRegistry
    pub use metadata::{
        asset_registry::events::{RegisteredAsset as RegisteredAssetEvent, UpdatedAsset as UpdatedAssetEvent},
        runtime_types::{
            interbtc_primitives::CustomMetadata as InterBtcAdditionalMetadata,
            orml_traits::asset_registry::AssetMetadata as GenericAssetMetadata,
        },
    };
    pub type AssetMetadata = GenericAssetMetadata<Balance, InterBtcAdditionalMetadata>;

    // BTCRelay
    pub use metadata::{
        btc_relay::events::StoreMainChainHeader as StoreMainChainHeaderEvent,
        runtime_types::{bitcoin::types::H256Le, btc_relay::pallet::Error as BtcRelayPalletError},
    };
    pub type InterBtcRichBlockHeader = metadata::runtime_types::btc_relay::types::RichBlockHeader<BlockNumber>;
    pub use metadata::runtime_types::bitcoin::address::PublicKey as BtcPublicKey;
    pub type BitcoinBlockHeight = u32;

    // ClientsInfo
    pub use metadata::runtime_types::clients_info::ClientRelease;

    // Issue
    pub use metadata::{
        issue::events::{
            CancelIssue as CancelIssueEvent, ExecuteIssue as ExecuteIssueEvent, RequestIssue as RequestIssueEvent,
        },
        runtime_types::{interbtc_primitives::issue::IssueRequestStatus, issue::pallet::Error as IssuePalletError},
    };
    pub type InterBtcIssueRequest =
        metadata::runtime_types::interbtc_primitives::issue::IssueRequest<AccountId, BlockNumber, Balance, CurrencyId>;

    // Loans
    pub use metadata::loans::events::{NewMarket as NewMarketEvent, UpdatedMarket as UpdatedMarketEvent};
    pub type LendingMarket = metadata::runtime_types::loans::types::Market<Balance>;

    // Oracle
    pub use metadata::{
        oracle::events::FeedValues as FeedValuesEvent, runtime_types::interbtc_primitives::oracle::Key as OracleKey,
    };

    // Redeem
    pub use metadata::{
        redeem::events::{ExecuteRedeem as ExecuteRedeemEvent, RequestRedeem as RequestRedeemEvent},
        runtime_types::interbtc_primitives::{redeem::RedeemRequestStatus, replace::ReplaceRequestStatus},
    };
    pub type InterBtcRedeemRequest = metadata::runtime_types::interbtc_primitives::redeem::RedeemRequest<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
    >;

    // Replace
    pub use metadata::replace::events::{
        AcceptReplace as AcceptReplaceEvent, CancelReplace as CancelReplaceEvent,
        ExecuteReplace as ExecuteReplaceEvent, RequestReplace as RequestReplaceEvent,
        WithdrawReplace as WithdrawReplaceEvent,
    };
    pub type InterBtcReplaceRequest = metadata::runtime_types::interbtc_primitives::replace::ReplaceRequest<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
    >;

    // Security
    pub use metadata::security::events::UpdateActiveBlock as UpdateActiveBlockEvent;

    // System
    pub use metadata::runtime_types::frame_system::pallet::Error as SystemPalletError;

    // Tokens
    pub use metadata::tokens::events::Endowed as EndowedEvent;

    // VaultRegistry
    pub use metadata::{
        runtime_types::vault_registry::{pallet::Error as VaultRegistryPalletError, types::VaultStatus},
        vault_registry::events::{LiquidateVault as LiquidateVaultEvent, RegisterVault as RegisterVaultEvent},
    };
    pub type InterBtcVault =
        metadata::runtime_types::vault_registry::types::Vault<AccountId, BlockNumber, Balance, CurrencyId, FixedU128>;
    pub type InterBtcVaultStatic = metadata::runtime_types::vault_registry::types::Vault<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
        Static<FixedU128>,
    >;
    pub type VaultId = metadata::runtime_types::interbtc_primitives::VaultId<AccountId, CurrencyId>;
    pub type VaultCurrencyPair = metadata::runtime_types::interbtc_primitives::VaultCurrencyPair<CurrencyId>;

    impl From<InterBtcVaultStatic> for InterBtcVault {
        fn from(val: InterBtcVaultStatic) -> Self {
            let InterBtcVaultStatic {
                id,
                status,
                banned_until,
                secure_collateral_threshold,
                to_be_issued_tokens,
                issued_tokens,
                to_be_redeemed_tokens,
                to_be_replaced_tokens,
                replace_collateral,
                active_replace_collateral,
                liquidated_collateral,
            } = val;

            InterBtcVault {
                id,
                status,
                banned_until,
                secure_collateral_threshold: secure_collateral_threshold.map(|static_value| *static_value),
                to_be_issued_tokens,
                issued_tokens,
                to_be_redeemed_tokens,
                to_be_replaced_tokens,
                replace_collateral,
                active_replace_collateral,
                liquidated_collateral,
            }
        }
    }

    #[cfg(feature = "parachain-metadata-interlay")]
    pub type EncodedCall = metadata::runtime_types::interlay_runtime_parachain::RuntimeCall;
    #[cfg(feature = "parachain-metadata-kintsugi")]
    pub type EncodedCall = metadata::runtime_types::kintsugi_runtime_parachain::RuntimeCall;

    pub type InterBtcHeader = <InterBtcRuntime as Config>::Header;

    pub use metadata::runtime_types::bounded_collections::bounded_vec::BoundedVec;
    pub type KeyStorageAddress<T> = Address<StaticStorageMapKey, T, (), (), Yes>;
}

pub struct RawBlockHeader(pub Vec<u8>);

impl RawBlockHeader {
    pub fn hash(&self) -> crate::H256Le {
        module_bitcoin::utils::sha256d_le(&self.0).into()
    }
}

impl From<[u8; 33]> for crate::BtcPublicKey {
    fn from(input: [u8; 33]) -> Self {
        crate::BtcPublicKey(input)
    }
}

mod currency_id {
    use super::*;
    use crate::Error;

    pub trait CurrencyIdExt {
        fn inner(&self) -> Result<primitives::TokenSymbol, Error>;
    }

    impl CurrencyIdExt for CurrencyId {
        fn inner(&self) -> Result<primitives::TokenSymbol, Error> {
            match self {
                Token(x) => Ok(*x),
                _ => Err(Error::CurrencyNotFound),
            }
        }
    }
}

pub trait PrettyPrint {
    fn pretty_print(&self) -> String;
}

mod account_id {
    use super::*;
    use sp_core::crypto::Ss58Codec;
    impl PrettyPrint for AccountId {
        fn pretty_print(&self) -> String {
            self.0.to_ss58check_with_version(SS58_PREFIX.into())
        }
    }
}

mod vault_id {
    use super::*;

    type RichVaultId = primitives::VaultId<AccountId, primitives::CurrencyId>;

    impl crate::VaultId {
        pub fn new(account_id: AccountId, collateral_currency: CurrencyId, wrapped_currency: CurrencyId) -> Self {
            Self {
                account_id,
                currencies: VaultCurrencyPair {
                    collateral: collateral_currency,
                    wrapped: wrapped_currency,
                },
            }
        }

        pub fn collateral_currency(&self) -> CurrencyId {
            self.currencies.collateral
        }

        pub fn wrapped_currency(&self) -> CurrencyId {
            self.currencies.wrapped
        }
    }

    impl PrettyPrint for VaultId {
        fn pretty_print(&self) -> String {
            let collateral_currency: CurrencyId = self.collateral_currency();
            let wrapped_currency: CurrencyId = self.wrapped_currency();
            format!(
                "{}[{}->{}]",
                self.account_id.pretty_print(),
                collateral_currency.symbol().unwrap_or_default(),
                wrapped_currency.symbol().unwrap_or_default(),
            )
        }
    }

    impl From<crate::VaultId> for RichVaultId {
        fn from(value: crate::VaultId) -> Self {
            Self {
                account_id: value.account_id,
                currencies: primitives::VaultCurrencyPair {
                    collateral: value.currencies.collateral,
                    wrapped: value.currencies.wrapped,
                },
            }
        }
    }

    impl From<RichVaultId> for crate::VaultId {
        fn from(value: RichVaultId) -> Self {
            Self {
                account_id: value.account_id,
                currencies: crate::VaultCurrencyPair {
                    collateral: value.currencies.collateral,
                    wrapped: value.currencies.wrapped,
                },
            }
        }
    }

    impl serde::Serialize for crate::VaultId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let value: RichVaultId = self.clone().into();
            value.serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for crate::VaultId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = RichVaultId::deserialize(deserializer)?;
            Ok(value.into())
        }
    }

    impl std::hash::Hash for crate::VaultId {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            let vault: RichVaultId = self.clone().into();
            vault.hash(state)
        }
    }
}

mod h256_le {
    use super::*;

    pub type RichH256Le = module_bitcoin::types::H256Le;

    impl From<RichH256Le> for crate::H256Le {
        fn from(value: RichH256Le) -> Self {
            Self {
                content: value.to_bytes_le(),
            }
        }
    }

    impl From<crate::H256Le> for RichH256Le {
        fn from(value: crate::H256Le) -> Self {
            Self::from_bytes_le(&value.content)
        }
    }

    impl crate::H256Le {
        pub fn from_bytes_le(bytes: &[u8]) -> H256Le {
            RichH256Le::from_bytes_le(bytes).into()
        }
        pub fn to_bytes_le(&self) -> [u8; 32] {
            RichH256Le::to_bytes_le(&self.clone().into())
        }
        pub fn is_zero(&self) -> bool {
            RichH256Le::is_zero(&self.clone().into())
        }
        pub fn to_hex_le(&self) -> String {
            RichH256Le::to_hex_le(&self.clone().into())
        }
    }
}
