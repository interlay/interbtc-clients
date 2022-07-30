use crate::error::Error;
use bytes::Bytes;
use codec::Decode;
use jsonrpsee::{
    core::client::{Client as WsClient, ClientT},
    rpc_params,
    ws_client::WsClientBuilder,
};
use reqwest::Url;
use sp_core::{Bytes as SpCoreBytes, H256};
use sp_core_hashing::twox_128;

use std::{
    convert::TryInto,
    fmt::Debug,
    fs::{self, File},
    io::{copy, Cursor},
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str,
    time::Duration,
};

use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};

use async_trait::async_trait;

pub const PARACHAIN_MODULE: &str = "VaultRegistry";
pub const CURRENT_RELEASE_STORAGE_ITEM: &str = "CurrentClientRelease";
pub const PENDING_RELEASE_STORAGE_ITEM: &str = "PendingClientRelease";
pub const BLOCK_TIME: Duration = Duration::from_secs(6);

#[derive(Decode, Default, Eq, PartialEq, Debug, Clone)]
pub struct ClientRelease {
    pub uri: String,
    pub code_hash: H256,
}

#[derive(Default, Eq, PartialEq, Debug, Clone)]
pub struct DownloadedRelease {
    pub release: ClientRelease,
    pub path: PathBuf,
    pub bin_name: String,
}

pub struct Vaultvisor {
    parachain_rpc: WsClient,
    vault_args: Vec<String>,
    child_proc: Option<Child>,
    downloaded_release: Option<DownloadedRelease>,
    download_path: PathBuf,
}

impl Vaultvisor {
    pub fn new(parachain_rpc: WsClient, vault_args: Vec<String>, download_path: PathBuf) -> Self {
        Self {
            parachain_rpc,
            vault_args,
            child_proc: None,
            downloaded_release: None,
            download_path,
        }
    }
}

pub async fn run(vaultvisor: &mut impl VaultvisorUtils) -> Result<(), Error> {
    // Create all directories for the `download_path` if they don't already exist.
    fs::create_dir_all(&vaultvisor.download_path())?;
    let release = vaultvisor.try_get_release(false).await?.expect("No current release");
    // WARNING: This will overwrite any pre-existing binary with the same name
    // TODO: Check if a release with the same version is already at the `download_path`
    vaultvisor.download_binary(release).await?;

    vaultvisor.run_binary().await?;

    loop {
        if let Some(new_release) = vaultvisor.try_get_release(false).await? {
            let maybe_downloaded_release = vaultvisor.downloaded_release();
            let downloaded_release = maybe_downloaded_release.as_ref().ok_or(Error::NoDownloadedRelease)?;
            if new_release.uri != downloaded_release.release.uri {
                // Wait for child process to finish completely.
                // To ensure there can't be two vault processes using the same Bitcoin wallet.
                vaultvisor.terminate_proc_and_wait()?;

                // Delete old release
                vaultvisor.delete_downloaded_release()?;

                // Download new release
                vaultvisor.download_binary(new_release).await?;

                // Run the downloaded release
                vaultvisor.run_binary().await?;
            }
        }
        tokio::time::sleep(BLOCK_TIME).await;
    }
}

#[async_trait]
pub trait VaultvisorUtils {
    fn parachain_rpc(&self) -> &WsClient;
    fn vault_args(&self) -> &Vec<String>;
    fn child_proc(&self) -> &Option<Child>;
    fn downloaded_release(&self) -> &Option<DownloadedRelease>;
    fn download_path(&self) -> &PathBuf;
    async fn try_get_release(&self, pending: bool) -> Result<Option<ClientRelease>, Error>;
    async fn download_binary(&mut self, release: ClientRelease) -> Result<(), Error>;
    fn uri_to_bin_path(&self, uri: &String) -> Result<(String, PathBuf), Error>;
    fn delete_downloaded_release(&mut self) -> Result<(), Error>;
    async fn run_binary(&mut self) -> Result<(), Error>;
    fn terminate_proc_and_wait(&mut self) -> Result<(), Error>;
    async fn get_request_bytes(url: String) -> Result<Bytes, Error>;
    async fn ws_client(url: &str) -> Result<WsClient, Error>;
}

#[async_trait]
impl VaultvisorUtils for Vaultvisor {
    fn parachain_rpc(&self) -> &WsClient {
        &self.parachain_rpc
    }

    fn vault_args(&self) -> &Vec<String> {
        &self.vault_args
    }

    fn child_proc(&self) -> &Option<Child> {
        &self.child_proc
    }

    fn downloaded_release(&self) -> &Option<DownloadedRelease> {
        &self.downloaded_release
    }

    fn download_path(&self) -> &PathBuf {
        &self.download_path
    }

    async fn try_get_release(&self, pending: bool) -> Result<Option<ClientRelease>, Error> {
        let storage_item = if pending {
            PENDING_RELEASE_STORAGE_ITEM
        } else {
            CURRENT_RELEASE_STORAGE_ITEM
        };
        let storage_key = Self::compute_storage_key(PARACHAIN_MODULE.to_string(), storage_item.to_string());
        Ok(Self::read_chain_storage::<ClientRelease>(self.parachain_rpc(), Some(storage_key)).await?)
    }

    async fn run_binary(&mut self) -> Result<(), Error> {
        // Ensure there is no other child running
        if self.child_proc.is_some() {
            return Err(Error::ChildProcessExists);
        }
        let downloaded_release = self.downloaded_release.as_ref().ok_or(Error::NoDownloadedRelease)?;
        let mut child = Command::new(downloaded_release.path.as_os_str())
            .args(self.vault_args.clone())
            .stdout(Stdio::inherit())
            .spawn()?;
        self.child_proc = Some(child);
        Ok(())
    }

    async fn download_binary(&mut self, release: ClientRelease) -> Result<(), Error> {
        let (bin_name, bin_path) = self.uri_to_bin_path(&release.uri)?;
        log::info!("Downloading {} at: {:?}", bin_name, bin_path);
        let mut bin_file = File::create(bin_path.clone())?;

        let bytes = Self::get_request_bytes(release.uri.clone()).await?;
        let mut content = Cursor::new(bytes);

        copy(&mut content, &mut bin_file)?;

        // Make the binary executable.
        // The set permissions are: -rwx------
        fs::set_permissions(bin_path.clone(), fs::Permissions::from_mode(0o700))?;

        self.downloaded_release = Some(DownloadedRelease {
            release,
            path: bin_path,
            bin_name: bin_name.to_string(),
        });
        Ok(())
    }

    fn uri_to_bin_path(&self, uri: &String) -> Result<(String, PathBuf), Error> {
        // Remove any trailing slashes from the release URI
        let parsed_uri = Url::parse(uri.trim_end_matches("/"))?;
        let bin_name = parsed_uri
            .path_segments()
            .and_then(|segments| segments.last())
            .and_then(|name| if name.is_empty() { None } else { Some(name) })
            .ok_or(Error::ClientNameDerivationError)?;
        let bin_path = self.download_path.join(bin_name);
        Ok((bin_name.to_string(), bin_path))
    }

    fn delete_downloaded_release(&mut self) -> Result<(), Error> {
        let release = self.downloaded_release().as_ref().ok_or(Error::NoDownloadedRelease)?;
        log::info!("Removing old release, with path {:?}", release.path);
        fs::remove_file(release.path.clone())?;
        self.downloaded_release = None;
        Ok(())
    }

    fn terminate_proc_and_wait(&mut self) -> Result<(), Error> {
        let child_proc = self.child_proc.as_mut().ok_or(Error::NoChildProcess)?;
        signal::kill(
            Pid::from_raw(child_proc.id().try_into().map_err(|_| Error::IntegerConversionError)?),
            Signal::SIGTERM,
        )?;

        match child_proc.wait() {
            Ok(exit_code) => log::info!("Outdated vault killed with exit code {}", exit_code),
            Err(error) => log::warn!("Outdated vault shutdown error: {}", error),
        };
        self.child_proc = None;
        Ok(())
    }

    async fn get_request_bytes(url: String) -> Result<Bytes, Error> {
        let response = reqwest::get(url.clone()).await?;
        Ok(response.bytes().await?)
    }

    async fn ws_client(url: &str) -> Result<WsClient, Error> {
        Ok(WsClientBuilder::default().build(url).await?)
    }
}

#[async_trait]
pub trait StorageReader {
    fn compute_storage_key(module: String, key: String) -> String;
    async fn query_storage(
        parachain_rpc: &WsClient,
        maybe_storage_key: Option<String>,
        method: String,
    ) -> Option<SpCoreBytes>;
    async fn read_chain_storage<T: Decode + Debug>(
        parachain_rpc: &WsClient,
        maybe_storage_key: Option<String>,
    ) -> Result<Option<T>, Error>;
}

#[async_trait]
impl StorageReader for Vaultvisor {
    fn compute_storage_key(module: String, key: String) -> String {
        let module = twox_128(module.as_bytes());
        let item = twox_128(key.as_bytes());
        let key = hex::encode([module, item].concat());
        format!("0x{}", key)
    }

    async fn query_storage(
        parachain_rpc: &WsClient,
        maybe_storage_key: Option<String>,
        method: String,
    ) -> Option<SpCoreBytes> {
        let params = maybe_storage_key.map_or(rpc_params![], |key| rpc_params![key]);
        parachain_rpc.request(method.as_str(), params).await.ok()
    }

    async fn read_chain_storage<T: Decode + Debug>(
        parachain_rpc: &WsClient,
        maybe_storage_key: Option<String>,
    ) -> Result<Option<T>, Error> {
        let enc_res = Self::query_storage(parachain_rpc, maybe_storage_key, "state_getStorage".to_string()).await;
        enc_res
            .map(|r| {
                let v = r.to_vec();
                T::decode(&mut &v[..])
            })
            .transpose()
            .map_err(Into::into)
    }
}
