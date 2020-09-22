use crate::timestamp::Timestamp;
use crate::timestamp::TimestampEventsDecoder;
use core::marker::PhantomData;
use parity_scale_codec::{Decode, Encode};
use std::fmt::Debug;
use substrate_subxt::system::System;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait ExchangeRateOracle: System + Timestamp {}

/// Current BTC/DOT exchange rate
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ExchangeRateStore<T: ExchangeRateOracle> {
    #[store(returns = u128)]
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
    pub rate: u128,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct SetExchangeRateEvent<T: ExchangeRateOracle> {
    pub sender: T::AccountId,
    pub rate: u128,
}