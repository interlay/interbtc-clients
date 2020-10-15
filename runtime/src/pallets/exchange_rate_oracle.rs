use crate::security::{Security, SecurityEventsDecoder};
use crate::timestamp::{Timestamp, TimestampEventsDecoder};
use core::marker::PhantomData;
use parity_scale_codec::{Codec, Decode, Encode, EncodeLike};
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait ExchangeRateOracle: Timestamp + Security {
    #[allow(non_camel_case_types)]
    type u128: Codec + EncodeLike + Member + Default;
}

/// Current BTC/DOT exchange rate
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ExchangeRateStore<T: ExchangeRateOracle> {
    #[store(returns = T::u128)]
    pub _runtime: PhantomData<T>,
}

/// Last exchange rate time
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct LastExchangeRateTimeStore<T: ExchangeRateOracle> {
    #[store(returns = T::Moment)]
    pub _runtime: PhantomData<T>,
}

/// Maximum delay for the exchange rate to be used
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct MaxDelayStore<T: ExchangeRateOracle> {
    #[store(returns = T::Moment)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SetExchangeRateCall<T: ExchangeRateOracle> {
    pub rate: T::u128,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct SetExchangeRateEvent<T: ExchangeRateOracle> {
    pub sender: T::AccountId,
    pub rate: T::u128,
}
