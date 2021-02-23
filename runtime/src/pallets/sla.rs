use super::Core;
pub use module_refund::RefundRequest;
use parity_scale_codec::Decode;
use serde::Serialize;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event};
#[module]
pub trait Sla: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct UpdateVaultSLAEvent<T: Sla> {
    pub vault_id: T::AccountId,
    pub new_sla: T::SignedFixedPoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct UpdateRelayerSLAEvent<T: Sla> {
    pub relayer_id: T::AccountId,
    pub new_sla: T::SignedFixedPoint,
}
