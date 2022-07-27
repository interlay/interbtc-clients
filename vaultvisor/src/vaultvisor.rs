use crate::error::Error;
use codec::{Decode, Encode};
use jsonrpsee::{
    core::client::{Client as WsClient, ClientT},
    rpc_params,
    ws_client::WsClientBuilder,
};
use reqwest::Url;
use sp_core::{Bytes, H256};
use sp_core_hashing::twox_128;

use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    io::{copy, Cursor},
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str,
    time::Duration,
};

pub const PARACHAIN_MODULE: &str = "VaultRegistry";
pub const CURRENT_RELEASE_STORAGE_ITEM: &str = "CurrentClientRelease";
pub const PENDING_RELEASE_STORAGE_ITEM: &str = "PendingClientRelease";
pub const BLOCK_TIME: Duration = Duration::from_secs(6);

#[derive(Encode, Decode, Default, Eq, PartialEq, Debug)]
pub struct ClientRelease {
    pub uri: String,
    pub code_hash: H256,
}

#[derive(Default, Eq, PartialEq, Debug)]
pub struct DownloadedRelease {
    pub release: ClientRelease,
    pub path: PathBuf,
    pub bin_name: String,
}

pub(crate) fn compute_storage_key(module: String, key: String) -> String {
    let module = twox_128(module.as_bytes());
    let item = twox_128(key.as_bytes());
    let key = hex::encode([module, item].concat());
    format!("0x{}", key)
}

pub async fn query_storage<'a>(
    ws_client: &'a WsClient,
    maybe_storage_key: Option<&str>,
    method: &str,
) -> Option<Bytes> {
    let params = maybe_storage_key.map_or(rpc_params![], |key| rpc_params![key]);
    ws_client.request(method, params).await.ok()
}

pub async fn read_chain_storage<T: Decode + Debug>(
    ws_client: &WsClient,
    maybe_storage_key: Option<&str>,
) -> Result<Option<T>, Error> {
    let enc_res = query_storage(ws_client, maybe_storage_key, "state_getStorage").await;
    enc_res
        .map(|r| {
            let v = r.to_vec();
            T::decode(&mut &v[..])
        })
        .transpose()
        .map_err(Into::into)
}

pub async fn get_release(ws_client: &WsClient, pending: bool) -> Result<Option<ClientRelease>, Error> {
    let storage_item = if pending {
        PENDING_RELEASE_STORAGE_ITEM
    } else {
        CURRENT_RELEASE_STORAGE_ITEM
    };
    let storage_key = compute_storage_key(PARACHAIN_MODULE.to_string(), storage_item.to_string());
    Ok(read_chain_storage::<ClientRelease>(ws_client, Some(storage_key.as_str())).await?)
}

pub async fn ws_client(url: &str) -> Result<WsClient, Error> {
    Ok(WsClientBuilder::default().build(url).await?)
}

pub async fn run_vault_binary(binary_name: &str, args: Vec<String>) -> Result<Child, Error> {
    let mut child = Command::new(format!("./{}", binary_name))
        .args(args)
        .stdout(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

/// Does not download if a file with the same name already exists
pub async fn try_download_client_binary(
    ws_client: &WsClient,
    pending: bool,
) -> Result<Option<DownloadedRelease>, Error> {
    let release = if let Some(r) = get_release(ws_client, pending).await? {
        r
    } else {
        return Ok(None);
    };
    let parsed_uri = Url::parse(&release.uri)?;
    let bin_name = parsed_uri
        .path_segments()
        .and_then(|segments| segments.last())
        .and_then(|name| if name.is_empty() { None } else { Some(name) })
        .ok_or(Error::ClientNameDerivationError)?;

    let dir = env::current_dir()?;
    let bin_path = dir.join(bin_name);
    if bin_path.as_path().exists() {
        log::warn!("Vault binary already exists, skipping download.");
        return Ok(Some(DownloadedRelease {
            release,
            path: bin_path,
            bin_name: bin_name.to_string(),
        }));
    }
    println!("Downloading {} at: '{:?}'", bin_name, bin_path);
    let mut bin_file = File::create(bin_path.clone())?;

    let response = reqwest::get(release.uri.clone()).await?;
    let mut content = Cursor::new(response.bytes().await?);

    copy(&mut content, &mut bin_file)?;

    // Make the binary executable.
    // The set permissions are: -rwx------
    fs::set_permissions(bin_path.clone(), fs::Permissions::from_mode(0o700))?;

    Ok(Some(DownloadedRelease {
        release,
        path: bin_path,
        bin_name: bin_name.to_string(),
    }))
}
