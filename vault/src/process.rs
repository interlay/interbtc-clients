use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    process,
    str::FromStr,
};

use crate::Error;
use runtime::AccountId;
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};

pub trait SystemProcess {
    fn refresh_process(&mut self, pid: Pid) -> bool;
    fn process_name(&self, pid: Pid) -> Result<String, Error>;
}

impl SystemProcess for System {
    fn refresh_process(&mut self, pid: Pid) -> bool {
        <Self as SystemExt>::refresh_process(self, pid)
    }

    fn process_name(&self, pid: Pid) -> Result<String, Error> {
        let process = <Self as SystemExt>::process(self, pid).ok_or_else(|| Error::ProcessNotFound(pid.to_string()))?;
        Ok(process.name().to_string())
    }
}

#[derive(Debug)]
pub struct PidFile {
    path: PathBuf,
    created_pidfile: bool,
}

impl PidFile {
    pub fn new(spec_name: &String, account_id: &AccountId) -> Self {
        Self {
            path: Self::compute_path(spec_name, account_id),
            created_pidfile: false,
        }
    }

    pub fn create(spec_name: &String, account_id: &AccountId, sys: &mut impl SystemProcess) -> Result<Self, Error> {
        let mut pid_file = Self::new(spec_name, account_id);
        if pid_file.path.exists() {
            let pid = pid_file.pid()?;
            if sys.refresh_process(pid) {
                match pid_name_matches_existing_client(sys, pid) {
                    Ok(true) => return Err(Error::ServiceAlreadyRunning(pid.as_u32())),
                    Ok(false) => (),
                    // There is a very small chance that a `pid` with a running process is killed exactly before
                    // `pid_name_matches_client` is run and `ProcessNotFound` is thrown. This is as if
                    // the `refresh_process` check had returned `false` (the pidfile process not running)
                    // so the error should not be propagated.
                    Err(Error::ProcessNotFound(_)) => (),
                    Err(e) => return Err(e),
                }
            }
            tracing::warn!(
                "Found existing PID file at: {}, but the process is no longer running.",
                pid_file
                    .path
                    .clone()
                    .into_os_string()
                    .into_string()
                    .map_err(|_| Error::OsStringError)?,
            );
        }

        tracing::info!(
            "Creating PID file at: {}",
            pid_file
                .path
                .clone()
                .into_os_string()
                .into_string()
                .map_err(|_| Error::OsStringError)?,
        );
        pid_file.set_pid(process::id())?;
        Ok(pid_file)
    }

    pub fn compute_path(spec_name: &String, account_id: &AccountId) -> PathBuf {
        let file_name = format!("{spec_name}_{account_id}.pid");
        // Use the default temporary directory of the OS
        std::env::temp_dir().join(file_name)
    }

    pub fn pid(&self) -> Result<Pid, Error> {
        let mut pid = fs::read_to_string(self.path.clone())?;
        pid = pid.strip_suffix('\n').unwrap_or(&pid).to_string();
        Ok(Pid::from_str(&pid)?)
    }

    pub fn set_pid(&mut self, pid: u32) -> Result<File, Error> {
        self.created_pidfile = true;
        let mut file = File::create(&self.path)?;
        file.write_all(format!("{pid}\n").as_bytes())?;
        file.sync_all()?;
        Ok(file)
    }

    pub fn remove(&mut self) -> Result<(), Error> {
        if self.created_pidfile {
            tracing::info!(
                "Removing PID file at: {}",
                self.path
                    .clone()
                    .into_os_string()
                    .into_string()
                    .map_err(|_| Error::OsStringError)?,
            );
            fs::remove_file(&self.path)?;
            self.path = PathBuf::default();
        } else {
            tracing::info!("No PID file created - no clean up required");
        }
        Ok(())
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            tracing::error!("Failed to remove PID file: {}", e);
        }
    }
}

pub fn pid_name_matches_existing_client(sys: &mut impl SystemProcess, pidfile_value: Pid) -> Result<bool, Error> {
    let client_pid = Pid::from_u32(process::id());
    Ok(sys.process_name(client_pid)? == sys.process_name(pidfile_value)?)
}

#[cfg(all(test, feature = "parachain-metadata-kintsugi"))]
mod tests {
    use super::*;
    use serial_test::serial;
    use sysinfo::Pid;

    macro_rules! assert_err {
        ($result:expr, $($err:tt)+) => {{
            match $result {
                $($err)+ => (),
                ref e => panic!("expected `{}` but got `{:?}`", stringify!($($err)+), e),
            }
        }};
    }

    mockall::mock! {
        System {}

        pub trait SystemProcess {
            fn refresh_process(&mut self, pid: Pid) -> bool;
            fn process_name(&self, pid: Pid) -> Result<String, Error>;
        }
    }

    #[test]
    #[serial]
    fn test_create_pid_file() {
        let dummy_account_id = AccountId::new(Default::default());
        let dummy_spec_name = "kintsugi-testnet".to_string();
        let mut sys = MockSystem::default();
        assert_eq!(
            PidFile::compute_path(&dummy_spec_name, &dummy_account_id).exists(),
            false
        );
        let pidfile = PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys).unwrap();
        assert_eq!(pidfile.path.exists(), true);
    }

    #[test]
    #[serial]
    fn test_overwrite_stale_pid_file() {
        let dummy_account_id = AccountId::new(Default::default());
        let dummy_spec_name = "kintsugi-testnet".to_string();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().once().return_const(false);
        let mut pidfile = PidFile::new(&dummy_spec_name, &dummy_account_id);

        // Some high pid value. PIDs are stored as i32.
        pidfile.set_pid(i32::MAX as u32).unwrap();

        let initial_pid = pidfile.pid().unwrap();
        let pidfile = PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys).unwrap();
        let final_pid = pidfile.pid().unwrap();
        assert_ne!(initial_pid, final_pid);
    }

    #[test]
    #[serial]
    fn test_pid_file_with_same_process() {
        let dummy_account_id = AccountId::new(Default::default());
        let dummy_spec_name = "kintsugi-testnet".to_string();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().once().return_const(true);
        let mut pidfile = PidFile::new(&dummy_spec_name, &dummy_account_id);
        pidfile.set_pid(process::id()).unwrap();

        sys.expect_process_name()
            .times(2)
            .returning(|_| Ok("vault".to_string()));

        #[allow(unused_variables)]
        let own_pid = process::id();
        assert_err!(
            PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys),
            #[allow(unused_variables)]
            Err(Error::ServiceAlreadyRunning(own_pid))
        );
    }

    #[test]
    #[serial]
    fn test_pid_file_overwrite_does_not_fail_when_process_is_not_running() {
        let dummy_account_id = AccountId::new(Default::default());
        let dummy_spec_name = "kintsugi-testnet".to_string();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().once().return_const(true);
        let mut pidfile = PidFile::new(&dummy_spec_name, &dummy_account_id);

        // Some high pid value. PIDs are stored as i32.
        pidfile.set_pid(i32::MAX as u32).unwrap();

        let own_pid = process::id();
        sys.expect_process_name().returning(move |pid| {
            if pid == Pid::from_u32(own_pid) {
                Ok("vault".to_string())
            } else {
                Err(Error::ProcessNotFound(pid.to_string()))
            }
        });
        PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys).unwrap();
    }

    #[test]
    #[serial]
    fn test_pidfile_removal() {
        let dummy_account_id = AccountId::new(Default::default());
        let dummy_spec_name = "kintsugi-testnet".to_string();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().return_const(true); // indicate the process still exists
        sys.expect_process_name().returning(|_| Ok("vault".to_string()));

        let path = {
            // simulate start vault: create pidfile
            let pidfile = PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys).unwrap();
            assert!(pidfile.path.exists());

            // simulate the start of a second vault: attempt to create pidfile
            {
                let _ = PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys);
            }

            // The second pidfile going out of scope should not cause the removal of the pidfile
            assert!(pidfile.path.exists());
            pidfile.path.clone()
        };

        // after the first pidfile goes out of scope, the file should be removed
        assert!(!path.exists());
    }
}
