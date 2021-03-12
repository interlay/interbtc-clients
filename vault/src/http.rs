use super::Error;
use bitcoin::BitcoinCoreApi;
use hex::FromHex;
use jsonrpc_http_server::{
    jsonrpc_core::{
        serde_json::Value, Error as JsonRpcError, ErrorCode as JsonRpcErrorCode, IoHandler, Params,
    },
    DomainsValidation, ServerBuilder,
};
use log::info;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    BtcPublicKey, Error as RuntimeError, ExchangeRateOraclePallet, FeePallet, FixedPointNumber,
    FixedPointTraits::{CheckedAdd, CheckedMul},
    PolkaBtcProvider, RedeemPallet, ReplacePallet, UtilFuncs, VaultRegistryPallet, HOURS,
};
use serde::{Deserialize, Deserializer};
use sp_arithmetic::FixedU128;
use sp_core::crypto::Ss58Codec;
use sp_core::H256;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

const HEALTH_DURATION: Duration = Duration::from_millis(5000);

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] pub(crate) Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

fn parse_params<T: Decode>(params: Params) -> Result<T, Error> {
    let raw: [RawBytes; 1] = params.parse()?;
    let req = Decode::decode(&mut &raw[0].0[..]).map_err(Error::CodecError)?;
    Ok(req)
}

fn handle_resp<T: Encode>(resp: Result<T, Error>) -> Result<Value, JsonRpcError> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(err) => Err(JsonRpcError {
            code: JsonRpcErrorCode::InternalError,
            message: err.to_string(),
            data: None,
        }),
    }
}

// NOTE: will return error on restart if vault doesn't have
// enough time to process open redeem requests
async fn _system_health(provider: &PolkaBtcProvider) -> Result<(), Error> {
    let result = match timeout(HEALTH_DURATION, provider.get_latest_block()).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RuntimeError(RuntimeError::from(err))),
    };

    let signed_block = result?.ok_or(Error::NoIncomingBlocks)?;
    let current_height: u128 = signed_block.block.header.number.into();
    let redeem_period = provider.get_redeem_period().await?;

    // TODO: parameterize based on expiry
    let has_uncompleted =
        provider.get_vault_redeem_requests(provider.get_account_id().clone()).await?
            .iter()
            .filter(|(_, request)| {
                !request.completed
                    && !request.cancelled
                    // ensure not expired
                    && Into::<u128>::into(request.opentime.saturating_add(redeem_period)) > current_height
            })
            .any(|(_, request)| {
                Into::<u128>::into(request.opentime.saturating_add(HOURS)) > current_height
            });

    if has_uncompleted {
        Err(Error::UncompletedRedeemRequests)
    } else {
        Ok(())
    }
}

#[derive(Encode, Decode, Debug)]
struct AccountIdJsonRpcResponse {
    account_id: String,
}

fn _account_id(provider: &PolkaBtcProvider) -> Result<AccountIdJsonRpcResponse, Error> {
    Ok(AccountIdJsonRpcResponse {
        account_id: provider.get_account_id().to_ss58check(),
    })
}

#[derive(Encode, Decode, Debug)]
struct ReplaceRequestJsonRpcRequest {
    amount: u128,
}

async fn _request_replace(provider: &PolkaBtcProvider, params: Params) -> Result<(), Error> {
    let req = parse_params::<ReplaceRequestJsonRpcRequest>(params)?;

    let amount_in_dot = provider.btc_to_dots(req.amount).await?;
    let griefing_collateral_percentage = provider.get_replace_griefing_collateral().await?;
    let griefing_collateral = calculate_for(amount_in_dot, griefing_collateral_percentage)?;
    let result = provider
        .request_replace(req.amount, griefing_collateral)
        .await;
    info!(
        "Requesting replace for amount = {} with griefing_collateral = {}: {:?}",
        req.amount, griefing_collateral, result
    );
    Ok(result.map(|_| ())?)
}

/// Take the `percentage` of an `amount`
fn calculate_for(amount: u128, percentage: FixedU128) -> Result<u128, Error> {
    // we add 0.5 before we do the final integer division to round the result we return.
    // note that unwrapping is safe because we use a constant
    let rounding_addition = FixedU128::checked_from_rational(1, 2).unwrap();

    FixedU128::checked_from_integer(amount)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_mul(&percentage)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_add(&rounding_addition)
        .ok_or(Error::ArithmeticOverflow)?
        .into_inner()
        .checked_div(FixedU128::accuracy())
        .ok_or(Error::ArithmeticUnderflow)
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcRequest {
    collateral: u128,
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcResponse {
    public_key: BtcPublicKey,
}

async fn _register_vault<B: BitcoinCoreApi + Clone>(
    provider: &PolkaBtcProvider,
    btc: &B,
    params: Params,
) -> Result<RegisterVaultJsonRpcResponse, Error> {
    let req = parse_params::<RegisterVaultJsonRpcRequest>(params)?;
    let public_key: BtcPublicKey = btc.get_new_public_key().await?;
    let result = provider
        .register_vault(req.collateral, public_key.clone())
        .await;
    info!(
        "Registering vault with bitcoind public_key {:?} and collateral = {}: {:?}",
        public_key, req.collateral, result
    );
    Ok(result.map(|_| RegisterVaultJsonRpcResponse { public_key })?)
}

#[derive(Encode, Decode, Debug)]
struct ChangeCollateralJsonRpcRequest {
    amount: u128,
}

async fn _lock_additional_collateral(
    provider: &PolkaBtcProvider,
    params: Params,
) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    let result = provider.lock_additional_collateral(req.amount).await;
    info!(
        "Locking additional collateral; amount {}: {:?}",
        req.amount, result
    );
    Ok(result?)
}

async fn _withdraw_collateral(provider: &PolkaBtcProvider, params: Params) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    let result = provider.withdraw_collateral(req.amount).await;
    info!(
        "Withdrawing collateral with amount {}: {:?}",
        req.amount, result
    );
    Ok(result?)
}

#[derive(Encode, Decode, Debug)]
struct WithdrawReplaceJsonRpcRequest {
    replace_id: H256,
}

async fn _withdraw_replace(provider: &PolkaBtcProvider, params: Params) -> Result<(), Error> {
    let req = parse_params::<WithdrawReplaceJsonRpcRequest>(params)?;
    let result = provider.withdraw_replace(req.replace_id).await;
    info!(
        "Withdrawing replace request {}: {:?}",
        req.replace_id, result
    );
    Ok(result?)
}

pub async fn start_http<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: PolkaBtcProvider,
    bitcoin_core: B,
    addr: SocketAddr,
    origin: String,
) {
    let mut io = IoHandler::default();
    {
        let provider = provider.clone();
        io.add_method("system_health", move |_| {
            let provider = provider.clone();
            async move { handle_resp(_system_health(&provider).await) }
        });
    }
    {
        let provider = provider.clone();
        io.add_method("account_id", move |_| {
            let provider = provider.clone();
            async move { handle_resp(_account_id(&provider)) }
        });
    }
    {
        let provider = provider.clone();
        io.add_method("request_replace", move |params| {
            let provider = provider.clone();
            async move { handle_resp(_request_replace(&provider, params).await) }
        });
    }
    {
        let provider = provider.clone();
        let bitcoin_core = bitcoin_core.clone();
        io.add_method("register_vault", move |params| {
            let provider = provider.clone();
            let bitcoin_core = bitcoin_core.clone();
            async move { handle_resp(_register_vault(&provider, &bitcoin_core, params).await) }
        });
    }
    {
        let provider = provider.clone();
        io.add_method("lock_additional_collateral", move |params| {
            let provider = provider.clone();
            async move { handle_resp(_lock_additional_collateral(&provider, params).await) }
        });
    }
    {
        let provider = provider.clone();
        io.add_method("withdraw_collateral", move |params| {
            let provider = provider.clone();
            async move { handle_resp(_withdraw_collateral(&provider, params).await) }
        });
    }
    {
        let provider = provider.clone();
        io.add_method("withdraw_replace", move |params| {
            let provider = provider.clone();
            async move { handle_resp(_withdraw_replace(&provider, params).await) }
        });
    }

    let server = ServerBuilder::new(io)
        .health_api(("/health", "system_health"))
        .rest_api(jsonrpc_http_server::RestApi::Unsecure)
        .cors(DomainsValidation::AllowOnly(vec![origin.into()]))
        .start_http(&addr)
        .expect("Unable to start RPC server");

    tokio::task::spawn_blocking(move || {
        server.wait();
    })
    .await
    .unwrap();
}
