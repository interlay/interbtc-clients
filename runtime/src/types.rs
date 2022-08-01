use crate::{metadata, Config, InterBtcRuntime, SS58_PREFIX};
pub use metadata_aliases::*;
use subxt::sp_core::{crypto::Ss58Codec, sr25519::Pair as KeyPair};

pub use primitives::{
    CurrencyId,
    CurrencyId::{ForeignAsset, Token},
    TokenSymbol::{self, DOT, IBTC, INTR, KBTC, KINT, KSM},
};

pub use currency_id::CurrencyIdExt;
pub use h256_le::RichH256Le;
pub use module_btc_relay::{RichBlockHeader, MAIN_CHAIN_ID};

pub type AccountId = subxt::sp_runtime::AccountId32;
pub type Balance = primitives::Balance;
pub type Index = u32;
pub type BlockNumber = u32;
pub type H160 = subxt::sp_core::H160;
pub type H256 = subxt::sp_core::H256;
pub type U256 = subxt::sp_core::U256;

pub type InterBtcSigner = subxt::PairSigner<InterBtcRuntime, KeyPair>;

pub type BtcAddress = module_btc_relay::BtcAddress;

pub type FixedU128 = sp_arithmetic::FixedU128;

mod metadata_aliases {
    use super::*;

    pub use metadata::runtime_types::bitcoin::address::PublicKey as BtcPublicKey;

    pub use metadata::runtime_types::interbtc_primitives::oracle::Key as OracleKey;

    pub use metadata::runtime_types::{
        bitcoin::types::RawBlockHeader,
        security::types::{ErrorCode, StatusCode},
        vault_registry::types::VaultStatus,
    };
    pub type InterBtcVault =
        metadata::runtime_types::vault_registry::types::Vault<AccountId, BlockNumber, Balance, CurrencyId, FixedU128>;
    pub type InterBtcRichBlockHeader = metadata::runtime_types::btc_relay::types::RichBlockHeader<BlockNumber>;
    pub type BitcoinBlockHeight = u32;

    pub use metadata::oracle::events::FeedValues as FeedValuesEvent;

    pub use metadata::issue::events::{
        CancelIssue as CancelIssueEvent, ExecuteIssue as ExecuteIssueEvent, RequestIssue as RequestIssueEvent,
    };

    pub use metadata::replace::events::{
        AcceptReplace as AcceptReplaceEvent, CancelReplace as CancelReplaceEvent,
        ExecuteReplace as ExecuteReplaceEvent, RequestReplace as RequestReplaceEvent,
        WithdrawReplace as WithdrawReplaceEvent,
    };

    pub use metadata::refund::events::{ExecuteRefund as ExecuteRefundEvent, RequestRefund as RequestRefundEvent};

    pub use metadata::redeem::events::{ExecuteRedeem as ExecuteRedeemEvent, RequestRedeem as RequestRedeemEvent};

    pub use metadata::security::events::UpdateActiveBlock as UpdateActiveBlockEvent;

    pub use metadata::vault_registry::events::{
        DepositCollateral as DepositCollateralEvent, LiquidateVault as LiquidateVaultEvent,
        RegisterAddress as RegisterAddressEvent, RegisterVault as RegisterVaultEvent,
    };

    pub use metadata::btc_relay::events::StoreMainChainHeader as StoreMainChainHeaderEvent;

    pub use metadata::tokens::events::Endowed as EndowedEvent;

    pub use metadata::runtime_types::{
        interbtc_primitives::CustomMetadata as InterBtcAdditionalMetadata,
        orml_traits::asset_registry::AssetMetadata as GenericAssetMetadata,
    };
    pub type AssetMetadata = GenericAssetMetadata<Balance, InterBtcAdditionalMetadata>;

    pub use metadata::runtime_types::{
        btc_relay::pallet::Error as BtcRelayPalletError, frame_system::pallet::Error as SystemPalletError,
        issue::pallet::Error as IssuePalletError, redeem::pallet::Error as RedeemPalletError,
        security::pallet::Error as SecurityPalletError,
    };

    pub use metadata::runtime_types::bitcoin::types::H256Le;

    pub type InterBtcHeader = <InterBtcRuntime as Config>::Header;

    pub type InterBtcIssueRequest =
        metadata::runtime_types::interbtc_primitives::issue::IssueRequest<AccountId, BlockNumber, Balance, CurrencyId>;
    pub use metadata::runtime_types::interbtc_primitives::issue::IssueRequestStatus;
    pub type InterBtcRedeemRequest = metadata::runtime_types::interbtc_primitives::redeem::RedeemRequest<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
    >;
    pub use metadata::runtime_types::interbtc_primitives::{
        redeem::RedeemRequestStatus, replace::ReplaceRequestStatus,
    };
    pub type InterBtcRefundRequest =
        metadata::runtime_types::interbtc_primitives::refund::RefundRequest<AccountId, Balance, CurrencyId>;
    pub type InterBtcReplaceRequest = metadata::runtime_types::interbtc_primitives::replace::ReplaceRequest<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
    >;
    pub type VaultId = metadata::runtime_types::interbtc_primitives::VaultId<AccountId, CurrencyId>;
    pub type VaultCurrencyPair = metadata::runtime_types::interbtc_primitives::VaultCurrencyPair<CurrencyId>;

    #[cfg(feature = "parachain-metadata-interlay")]
    pub type EncodedCall = metadata::runtime_types::interlay_runtime_parachain::Call;
    #[cfg(feature = "parachain-metadata-kintsugi")]
    pub type EncodedCall = metadata::runtime_types::kintsugi_runtime_parachain::Call;
    #[cfg(feature = "parachain-metadata-interlay-testnet")]
    pub type EncodedCall = metadata::runtime_types::testnet_interlay_runtime_parachain::Call;
    #[cfg(feature = "parachain-metadata-kintsugi-testnet")]
    pub type EncodedCall = metadata::runtime_types::testnet_kintsugi_runtime_parachain::Call;
    #[cfg(feature = "standalone-metadata")]
    pub type EncodedCall = metadata::runtime_types::interbtc_runtime_standalone::Call;

    pub use metadata::runtime_types::security::pallet::Call as SecurityCall;
}

impl crate::RawBlockHeader {
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
                ForeignAsset(_) => Err(Error::CurrencyNotFound),
            }
        }
    }
}

pub trait PrettyPrint {
    fn pretty_print(&self) -> String;
}

mod account_id {
    use super::*;

    impl PrettyPrint for AccountId {
        fn pretty_print(&self) -> String {
            self.to_ss58check_with_version(SS58_PREFIX.into())
        }
    }
}

mod vault_id {
    use super::*;
    use primitives::CurrencyInfo;

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
                collateral_currency
                    .inner()
                    .map(|i| i.symbol().to_string())
                    .unwrap_or_default(),
                wrapped_currency
                    .inner()
                    .map(|i| i.symbol().to_string())
                    .unwrap_or_default()
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

mod dispatch_error {
    use crate::metadata::{
        runtime_types::sp_runtime::{ArithmeticError, ModuleError, TokenError, TransactionalError},
        DispatchError,
    };

    type RichTokenError = sp_runtime::TokenError;
    type RichArithmeticError = sp_runtime::ArithmeticError;
    type RichDispatchError = sp_runtime::DispatchError;
    type RichModuleError = sp_runtime::ModuleError;
    type RichTransactionalError = sp_runtime::TransactionalError;

    macro_rules! convert_enum{($src: ident, $dst: ident, $($variant: ident,)*)=> {
        impl From<$src> for $dst {
            fn from(src: $src) -> Self {
                match src {
                    $($src::$variant => Self::$variant,)*
                }
            }
        }
    }}

    convert_enum!(
        RichTokenError,
        TokenError,
        NoFunds,
        WouldDie,
        BelowMinimum,
        CannotCreate,
        UnknownAsset,
        Frozen,
        Unsupported,
    );

    convert_enum!(
        RichArithmeticError,
        ArithmeticError,
        Underflow,
        Overflow,
        DivisionByZero,
    );

    convert_enum!(RichTransactionalError, TransactionalError, LimitReached, NoLayer,);

    impl From<RichDispatchError> for DispatchError {
        fn from(value: RichDispatchError) -> Self {
            match value {
                RichDispatchError::Other(_) => DispatchError::Other,
                RichDispatchError::CannotLookup => DispatchError::CannotLookup,
                RichDispatchError::BadOrigin => DispatchError::BadOrigin,
                RichDispatchError::Module(RichModuleError { index, error, .. }) => {
                    DispatchError::Module(ModuleError { index, error })
                }
                RichDispatchError::ConsumerRemaining => DispatchError::ConsumerRemaining,
                RichDispatchError::NoProviders => DispatchError::NoProviders,
                RichDispatchError::TooManyConsumers => DispatchError::TooManyConsumers,
                RichDispatchError::Token(token_error) => DispatchError::Token(token_error.into()),
                RichDispatchError::Arithmetic(arithmetic_error) => DispatchError::Arithmetic(arithmetic_error.into()),
                RichDispatchError::Transactional(transactional_error) => {
                    DispatchError::Transactional(transactional_error.into())
                }
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for DispatchError {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = RichDispatchError::deserialize(deserializer)?;
            Ok(value.into())
        }
    }
}
