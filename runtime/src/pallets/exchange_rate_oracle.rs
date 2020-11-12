use super::{Core, CoreEventsDecoder};
use crate::timestamp::{Timestamp, TimestampEventsDecoder};
use core::marker::PhantomData;
use module_exchange_rate_oracle::BtcTxFeesPerByte;
use parity_scale_codec::{Decode, Encode};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait ExchangeRateOracle: Core + Timestamp {}

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

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SetBtcTxFeesPerByteCall<T: ExchangeRateOracle> {
    pub fast: u32,
    pub half: u32,
    pub hour: u32,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Event, Decode)]
pub struct SetBtcTxFeesPerByteEvent<T: ExchangeRateOracle> {
    pub sender: T::AccountId,
    pub fast: u32,
    pub half: u32,
    pub hour: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct SatoshiPerBytesStore<T: ExchangeRateOracle> {
    #[store(returns = BtcTxFeesPerByte)]
    pub _runtime: PhantomData<T>,
}
