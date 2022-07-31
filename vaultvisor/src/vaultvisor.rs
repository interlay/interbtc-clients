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
    os::unix::prelude::PermissionsExt,
    path::PathBuf,
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
    fn child_proc(&mut self) -> &mut Option<Child>;
    fn set_child_proc(&mut self, child_proc: Child);
    fn downloaded_release(&self) -> &Option<DownloadedRelease>;
    fn set_downloaded_release(&mut self, downloaded_release: DownloadedRelease);
    fn download_path(&self) -> &PathBuf;
    fn set_download_path(&mut self, download_path: PathBuf);
    async fn try_get_release(&self, pending: bool) -> Result<Option<ClientRelease>, Error>;
    async fn download_binary(&mut self, release: ClientRelease) -> Result<(), Error>;
    fn uri_to_bin_path(&self, uri: &String) -> Result<(String, PathBuf), Error>;
    fn delete_downloaded_release(&mut self) -> Result<(), Error>;
    async fn run_binary(&mut self) -> Result<(), Error>;
    fn terminate_proc_and_wait(&mut self) -> Result<(), Error>;
    async fn get_request_bytes(&self, url: String) -> Result<Bytes, Error>;
}

#[async_trait]
impl VaultvisorUtils for Vaultvisor {
    fn parachain_rpc(&self) -> &WsClient {
        &self.parachain_rpc
    }

    fn vault_args(&self) -> &Vec<String> {
        &self.vault_args
    }

    fn child_proc(&mut self) -> &mut Option<Child> {
        &mut self.child_proc
    }

    fn set_child_proc(&mut self, child_proc: Child) {
        self.child_proc = Some(child_proc);
    }

    fn downloaded_release(&self) -> &Option<DownloadedRelease> {
        &self.downloaded_release
    }

    fn set_downloaded_release(&mut self, downloaded_release: DownloadedRelease) {
        self.downloaded_release = Some(downloaded_release);
    }

    fn download_path(&self) -> &PathBuf {
        &self.download_path
    }

    fn set_download_path(&mut self, download_path: PathBuf) {
        self.download_path = download_path;
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
        let downloaded_release = self.downloaded_release().as_ref().ok_or(Error::NoDownloadedRelease)?;
        let child = Command::new(downloaded_release.path.as_os_str())
            .args(self.vault_args.clone())
            .stdout(Stdio::inherit())
            .spawn()?;
        self.child_proc = Some(child);
        Ok(())
    }

    async fn download_binary(&mut self, release: ClientRelease) -> Result<(), Error> {
        let downloaded_release = download_binary(&*self, release).await?;
        self.set_downloaded_release(downloaded_release);
        Ok(())
    }

    fn uri_to_bin_path(&self, uri: &String) -> Result<(String, PathBuf), Error> {
        uri_to_bin_path(self, uri)
    }

    fn delete_downloaded_release(&mut self) -> Result<(), Error> {
        delete_downloaded_release(self)?;
        self.downloaded_release = None;
        Ok(())
    }

    fn terminate_proc_and_wait(&mut self) -> Result<(), Error> {
        terminate_proc_and_wait(self)?;
        self.child_proc = None;
        Ok(())
    }

    // Declaring as a static method would highly complicate mocking
    async fn get_request_bytes(&self, url: String) -> Result<Bytes, Error> {
        let response = reqwest::get(url.clone()).await?;
        Ok(response.bytes().await?)
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

pub async fn ws_client(url: &str) -> Result<WsClient, Error> {
    Ok(WsClientBuilder::default().build(url).await?)
}

async fn download_binary(
    vaultvisor: &impl VaultvisorUtils,
    release: ClientRelease,
) -> Result<DownloadedRelease, Error> {
    let (bin_name, bin_path) = vaultvisor.uri_to_bin_path(&release.uri)?;
    log::info!("Downloading {} at: {:?}", bin_name, bin_path);
    println!("Downloading {} at: {:?}", bin_name, bin_path);
    File::create(bin_path.clone())?;

    let bytes = vaultvisor.get_request_bytes(release.uri.clone()).await?;
    fs::write(&bin_path, &bytes)?;

    // Make the binary executable.
    // The set permissions are: -rwx------
    fs::set_permissions(bin_path.clone(), fs::Permissions::from_mode(0o700))?;

    Ok(DownloadedRelease {
        release,
        path: bin_path,
        bin_name: bin_name.to_string(),
    })
}

fn uri_to_bin_path(vaultvisor: &impl VaultvisorUtils, uri: &String) -> Result<(String, PathBuf), Error> {
    // Remove any trailing slashes from the release URI
    let parsed_uri = Url::parse(uri.trim_end_matches("/"))?;
    let bin_name = parsed_uri
        .path_segments()
        .and_then(|segments| segments.last())
        .and_then(|name| if name.is_empty() { None } else { Some(name) })
        .ok_or(Error::ClientNameDerivationError)?;
    let bin_path = vaultvisor.download_path().join(bin_name);
    Ok((bin_name.to_string(), bin_path))
}

fn delete_downloaded_release(vaultvisor: &impl VaultvisorUtils) -> Result<(), Error> {
    let release = vaultvisor
        .downloaded_release()
        .as_ref()
        .ok_or(Error::NoDownloadedRelease)?;
    log::info!("Removing old release, with path {:?}", release.path);
    fs::remove_file(release.path.clone())?;
    Ok(())
}

fn terminate_proc_and_wait(vaultvisor: &mut impl VaultvisorUtils) -> Result<u32, Error> {
    let child_proc = vaultvisor.child_proc().as_mut().ok_or(Error::NoChildProcess)?;
    signal::kill(
        Pid::from_raw(child_proc.id().try_into().map_err(|_| Error::IntegerConversionError)?),
        Signal::SIGTERM,
    )?;

    match child_proc.wait() {
        Ok(exit_code) => log::info!("Outdated vault killed with exit code {}", exit_code),
        Err(error) => log::warn!("Outdated vault shutdown error: {}", error),
    };
    Ok(child_proc.id())
}

#[cfg(test)]
mod tests {
    use sp_core::H256;
    use std::{
        convert::TryInto,
        fs::{self, File},
        os::unix::prelude::PermissionsExt,
        path::PathBuf,
        process::{Child, Command},
        str::FromStr,
    };

    use crate::{
        vaultvisor::{
            delete_downloaded_release, download_binary, terminate_proc_and_wait, ClientRelease, DownloadedRelease,
        },
        *,
    };

    use super::uri_to_bin_path;

    use sysinfo::{Pid, ProcessExt, ProcessStatus, System, SystemExt};

    mockall::mock! {
        Vaultvisor {}

        #[async_trait]
        pub trait VaultvisorUtils {
            fn parachain_rpc(&self) -> &WsClient;
            fn vault_args(&self) -> &Vec<String>;
            fn child_proc(&mut self) -> &mut Option<Child>;
            fn set_child_proc(&mut self, child_proc: Child);
            fn downloaded_release(&self) -> &Option<DownloadedRelease>;
            fn set_downloaded_release(&mut self, downloaded_release: DownloadedRelease);
            fn download_path(&self) -> &PathBuf;
            fn set_download_path(&mut self, download_path: PathBuf);
            async fn try_get_release(&self, pending: bool) -> Result<Option<ClientRelease>, Error>;
            async fn download_binary(&mut self, release: ClientRelease) -> Result<(), Error>;
            fn uri_to_bin_path(&self, uri: &String) -> Result<(String, PathBuf), Error>;
            fn delete_downloaded_release(&mut self) -> Result<(), Error>;
            async fn run_binary(&mut self) -> Result<(), Error>;
            fn terminate_proc_and_wait(&mut self) -> Result<(), Error>;
            async fn get_request_bytes(&self, url: String) -> Result<Bytes, Error>;
        }
    }

    #[tokio::test]
    async fn test_vaultvisor_download_binary() {
        let mut vaultvisor = MockVaultvisor::default();
        let mock_path = PathBuf::from_str("./vault-standalone-metadata").unwrap();
        let mock_bin_name = "vault-standalone-metadata".to_string();

        let client_release = ClientRelease {
            uri: "https://github.com/interlay/interbtc-clients/releases/download/1.15.0/vault-standalone-metadata"
                .to_string(),
            code_hash: H256::default(),
        };
        vaultvisor.expect_uri_to_bin_path().returning(|_| {
            Ok((
                "vault-standalone-metadata".to_string(),
                PathBuf::from_str("./vault-standalone-metadata").unwrap(),
            ))
        });
        vaultvisor
            .expect_get_request_bytes()
            .returning(|_| Ok(Bytes::from_static(&[1, 2, 3, 4])));

        let downloaded_release = download_binary(&vaultvisor, client_release.clone()).await.unwrap();
        assert_eq!(
            downloaded_release,
            DownloadedRelease {
                release: client_release,
                path: mock_path.clone(),
                bin_name: mock_bin_name
            }
        );

        let meta = std::fs::metadata(mock_path.clone()).unwrap();
        // The POSIX mode returned by `Permissions::mode()` contains two kinds of
        // information: the file type code, and the access permission bits.
        // Since the executable is a regular file, its file type code fits the
        // `S_IFREG` bit mask (`0o0100000`).
        // Sources:
        // - https://www.gnu.org/software/libc/manual/html_node/Testing-File-Type.html
        // - https://en.wikibooks.org/wiki/C_Programming/POSIX_Reference/sys/stat.h
        assert_eq!(
            meta.permissions(),
            // Expect the mode to include both the file type (`0100000`) and file permissions (`700`).
            fs::Permissions::from_mode(0o0100700)
        );

        let file_content = fs::read(mock_path.clone()).unwrap();
        assert_eq!(file_content, vec![1, 2, 3, 4]);

        // Remove mock from file system
        fs::remove_file(mock_path).unwrap();
    }

    #[tokio::test]
    async fn test_vaultvisor_uri_to_bin_path() {
        let mut vaultvisor = MockVaultvisor::default();
        vaultvisor
            .expect_download_path()
            .return_const(PathBuf::from_str("./mock_download_dir").unwrap());
        let uri = "https://github.com/interlay/interbtc-clients/releases/download/1.15.0/vault-standalone-metadata"
            .to_string();
        let (bin_name, bin_path) = uri_to_bin_path(&vaultvisor, &uri).unwrap();
        assert_eq!(bin_name, "vault-standalone-metadata".to_string());
        assert_eq!(
            bin_path,
            PathBuf::from_str("./mock_download_dir/vault-standalone-metadata").unwrap()
        );
    }

    #[tokio::test]
    async fn test_vaultvisor_delete_downloaded_release() {
        // Create dummy file
        let mock_path = PathBuf::from_str("./mock_file").unwrap();
        File::create(mock_path.clone()).unwrap();

        let mut vaultvisor = MockVaultvisor::default();
        let downloaded_release = DownloadedRelease {
            release: ClientRelease {
                uri: String::default(),
                code_hash: H256::default(),
            },
            path: mock_path.clone(),
            bin_name: String::default(),
        };
        vaultvisor
            .expect_downloaded_release()
            .return_const(Some(downloaded_release));

        delete_downloaded_release(&vaultvisor).unwrap();
        assert_eq!(mock_path.exists(), false);
    }

    #[tokio::test]
    async fn test_vaultvisor_terminate_proc_and_wait() {
        // spawn long-running child process
        let mut vaultvisor = MockVaultvisor::default();
        vaultvisor
            .expect_child_proc()
            .returning(|| Some(Command::new("sleep").arg("100").spawn().unwrap()));
        let pid = terminate_proc_and_wait(&mut vaultvisor).unwrap();
        let pid_i32: i32 = pid.try_into().unwrap();
        let s = System::new_all();
        // Get all running processes
        let processes = s.processes();
        // Get the child process based on its pid
        let child_process = processes.get(&Pid::from(pid_i32));

        assert_eq!(child_process.is_none(), true);
    }
}
