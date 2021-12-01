use crate::{metadata, Config, InterBtcRuntime};
pub use metadata_aliases::*;
use subxt::{
    sp_core::{crypto::Ss58Codec, sr25519::Pair as KeyPair},
    PairSigner,
};

pub use h256_le::RichH256Le;
pub use module_btc_relay::{RichBlockHeader, MAIN_CHAIN_ID};

pub type AccountId = subxt::sp_runtime::AccountId32;
pub type Balance = primitives::Balance;
pub type Index = u32;
pub type BlockNumber = u32;
pub type H160 = subxt::sp_core::H160;
pub type H256 = subxt::sp_core::H256;
pub type U256 = subxt::sp_core::U256;

pub type RichCurrencyId = primitives::CurrencyId;

pub type InterBtcSigner = PairSigner<InterBtcRuntime, KeyPair>;

pub type BtcAddress = module_btc_relay::BtcAddress;

pub type FixedU128 = sp_arithmetic::FixedU128;

mod metadata_aliases {
    use super::*;

    pub type BtcPublicKey = metadata::runtime_types::bitcoin::address::PublicKey;

    pub type OracleKey = metadata::runtime_types::interbtc_primitives::oracle::Key;

    pub type StatusCode = metadata::runtime_types::security::types::StatusCode;
    pub type ErrorCode = metadata::runtime_types::security::types::ErrorCode;
    pub type RawBlockHeader = metadata::runtime_types::bitcoin::types::RawBlockHeader;
    pub type VaultStatus = metadata::runtime_types::vault_registry::types::VaultStatus;
    pub type InterBtcVault =
        metadata::runtime_types::vault_registry::types::Vault<AccountId, BlockNumber, Balance, CurrencyId>;
    pub type Wallet = metadata::runtime_types::vault_registry::types::Wallet;
    pub type InterBtcRichBlockHeader = metadata::runtime_types::btc_relay::types::RichBlockHeader<BlockNumber>;
    pub type BitcoinBlockHeight = u32;

    pub type FeedValuesEvent = metadata::oracle::events::FeedValues;

    pub type CancelIssueEvent = metadata::issue::events::CancelIssue;
    pub type ExecuteIssueEvent = metadata::issue::events::ExecuteIssue;
    pub type RequestIssueEvent = metadata::issue::events::RequestIssue;

    pub type AcceptReplaceEvent = metadata::replace::events::AcceptReplace;
    pub type ExecuteReplaceEvent = metadata::replace::events::ExecuteReplace;
    pub type RequestReplaceEvent = metadata::replace::events::RequestReplace;
    pub type WithdrawReplaceEvent = metadata::replace::events::WithdrawReplace;
    pub type CancelReplaceEvent = metadata::replace::events::CancelReplace;

    pub type RequestRefundEvent = metadata::refund::events::RequestRefund;
    pub type ExecuteRefundEvent = metadata::refund::events::ExecuteRefund;

    pub type RequestRedeemEvent = metadata::redeem::events::RequestRedeem;
    pub type ExecuteRedeemEvent = metadata::redeem::events::ExecuteRedeem;

    pub type UpdateActiveBlockEvent = metadata::security::events::UpdateActiveBlock;

    pub type RegisterVaultEvent = metadata::vault_registry::events::RegisterVault;
    pub type RegisterAddressEvent = metadata::vault_registry::events::RegisterAddress;
    pub type DepositCollateralEvent = metadata::vault_registry::events::DepositCollateral;
    pub type LiquidateVaultEvent = metadata::vault_registry::events::LiquidateVault;

    pub type StoreMainChainHeaderEvent = metadata::btc_relay::events::StoreMainChainHeader;

    pub type VaultTheftEvent = metadata::relay::events::VaultTheft;
    pub type VaultDoublePaymentEvent = metadata::relay::events::VaultDoublePayment;

    pub type EndowedEvent = metadata::tokens::events::Endowed;

    pub type BtcRelayPalletError = metadata::runtime_types::btc_relay::pallet::Error;
    pub type IssuePalletError = metadata::runtime_types::issue::pallet::Error;
    pub type RedeemPalletError = metadata::runtime_types::redeem::pallet::Error;
    pub type RelayPalletError = metadata::runtime_types::relay::pallet::Error;
    pub type SecurityPalletError = metadata::runtime_types::security::pallet::Error;

    pub type H256Le = metadata::runtime_types::bitcoin::types::H256Le;

    pub type InterBtcHeader = <InterBtcRuntime as Config>::Header;

    pub type InterBtcIssueRequest =
        metadata::runtime_types::interbtc_primitives::issue::IssueRequest<AccountId, BlockNumber, Balance, CurrencyId>;
    pub type IssueRequestStatus = metadata::runtime_types::interbtc_primitives::issue::IssueRequestStatus;
    pub type InterBtcRedeemRequest = metadata::runtime_types::interbtc_primitives::redeem::RedeemRequest<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
    >;
    pub type RedeemRequestStatus = metadata::runtime_types::interbtc_primitives::redeem::RedeemRequestStatus;
    pub type ReplaceRequestStatus = metadata::runtime_types::interbtc_primitives::replace::ReplaceRequestStatus;
    pub type InterBtcRefundRequest =
        metadata::runtime_types::interbtc_primitives::refund::RefundRequest<AccountId, Balance, CurrencyId>;
    pub type InterBtcReplaceRequest = metadata::runtime_types::interbtc_primitives::replace::ReplaceRequest<
        AccountId,
        BlockNumber,
        Balance,
        CurrencyId,
    >;
    pub type CurrencyId = metadata::runtime_types::interbtc_primitives::CurrencyId;
    pub type VaultId = metadata::runtime_types::interbtc_primitives::VaultId<AccountId, CurrencyId>;
    pub type VaultCurrencyPair = metadata::runtime_types::interbtc_primitives::VaultCurrencyPair<CurrencyId>;

    #[cfg(feature = "parachain-metadata")]
    pub type EncodedCall = metadata::runtime_types::interbtc_runtime_parachain::Call;
    #[cfg(not(feature = "parachain-metadata"))]
    pub type EncodedCall = metadata::runtime_types::interbtc_runtime_standalone::Call;

    pub type SecurityCall = metadata::runtime_types::security::pallet::Call;
}

impl crate::RawBlockHeader {
    pub fn hash(&self) -> crate::H256Le {
        module_bitcoin::utils::sha256d_le(&self.0).into()
    }
}

impl From<[u8; 33]> for crate::BtcPublicKey {
    fn from(input: [u8; 33]) -> Self {
        crate::BtcPublicKey { 0: input }
    }
}

mod currency_id {
    impl Copy for crate::CurrencyId {}

    impl Into<primitives::CurrencyId> for crate::CurrencyId {
        fn into(self) -> primitives::CurrencyId {
            match self {
                Self::DOT => primitives::CurrencyId::DOT,
                Self::INTERBTC => primitives::CurrencyId::INTERBTC,
                Self::INTR => primitives::CurrencyId::INTR,
                Self::KBTC => primitives::CurrencyId::KBTC,
                Self::KINT => primitives::CurrencyId::KINT,
                Self::KSM => primitives::CurrencyId::KSM,
            }
        }
    }

    impl From<primitives::CurrencyId> for crate::CurrencyId {
        fn from(value: primitives::CurrencyId) -> Self {
            match value {
                primitives::CurrencyId::DOT => Self::DOT,
                primitives::CurrencyId::INTERBTC => Self::INTERBTC,
                primitives::CurrencyId::INTR => Self::INTR,
                primitives::CurrencyId::KBTC => Self::KBTC,
                primitives::CurrencyId::KINT => Self::KINT,
                primitives::CurrencyId::KSM => Self::KSM,
            }
        }
    }

    impl serde::Serialize for crate::CurrencyId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let value: primitives::CurrencyId = (*self).into();
            value.serialize(serializer)
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

        pub fn pretty_printed(&self) -> String {
            let collateral_currency: RichCurrencyId = self.collateral_currency().into();
            let wrapped_currency: RichCurrencyId = self.wrapped_currency().into();
            format!(
                "{}[{}->{}]",
                self.account_id.to_ss58check(),
                collateral_currency.name(),
                wrapped_currency.name()
            )
        }
    }

    impl Into<RichVaultId> for crate::VaultId {
        fn into(self) -> RichVaultId {
            primitives::VaultId {
                account_id: self.account_id,
                currencies: primitives::VaultCurrencyPair {
                    collateral: self.currencies.collateral.into(),
                    wrapped: self.currencies.wrapped.into(),
                },
            }
        }
    }

    impl From<RichVaultId> for crate::VaultId {
        fn from(value: RichVaultId) -> Self {
            Self {
                account_id: value.account_id,
                currencies: crate::VaultCurrencyPair {
                    collateral: value.currencies.collateral.into(),
                    wrapped: value.currencies.wrapped.into(),
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
            let value = primitives::VaultId::<AccountId, primitives::CurrencyId>::deserialize(deserializer)?;
            Ok(value.into())
        }
    }

    impl std::hash::Hash for crate::VaultId {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            let vault: primitives::VaultId<AccountId, primitives::CurrencyId> = self.clone().into();
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

    impl Into<RichH256Le> for crate::H256Le {
        fn into(self) -> RichH256Le {
            RichH256Le::from_bytes_le(&self.content)
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
