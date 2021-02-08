use crate::error::Error;
use crate::http::RawBytes;
use jsonrpc_core_client::TypedClient;
use jsonrpc_http_server::jsonrpc_core::Value;
use parity_scale_codec::{Decode, Encode};
use runtime::AccountId;

#[derive(Encode, Decode, Debug, Clone, serde::Serialize)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
}

pub async fn get_funding(
    faucet_connection: TypedClient,
    staked_relayer_id: AccountId,
) -> Result<(), Error> {
    let funding_request = FundAccountJsonRpcRequest {
        account_id: staked_relayer_id,
    };
    let eq = format!("0x{}", hex::encode(funding_request.encode()));
    faucet_connection
        .call_method::<Vec<String>, Value>("fund_account", "", vec![eq.clone()])
        .await?;
    Ok(())
}

pub async fn get_faucet_allowance(
    faucet_connection: TypedClient,
    allowance_type: &str,
) -> Result<u128, Error> {
    let raw_allowance = faucet_connection
        .call_method::<(), RawBytes>(&allowance_type, "", ())
        .await?;
    Ok(Decode::decode(&mut &raw_allowance.0[..])?)
}
