use parity_scale_codec::{Decode, Encode};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Encode, Decode)]
pub struct AllowanceAmount {
    pub symbol: String,
    pub amount: u128,
}

impl AllowanceAmount {
    pub fn new(symbol: String, amount: u128) -> Self {
        Self { symbol, amount }
    }
}

pub type Allowance = Vec<AllowanceAmount>;
