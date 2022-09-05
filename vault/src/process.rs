use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process,
    str::FromStr,
};

use service::Error;
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

pub fn pid_file_path(spec_name: String, account_id: String) -> PathBuf {
    let file_name = format!("{}_{}.pid", spec_name, account_id);
    // Use the default temporary directory of the OS
    std::env::temp_dir().join(file_name)
}

pub fn try_create_pid_file(spec_name: String, account_id: String, sys: &mut System) -> Result<File, Error> {
    let path = pid_file_path(spec_name, account_id);
    try_create_pid_file_with_path(path, sys)
}

pub fn get_pid_from_file(path: &Path) -> Result<Pid, Error> {
    let mut pid = fs::read_to_string(path)?;
    pid = pid.strip_suffix('\n').unwrap_or(&pid).to_string();
    Ok(Pid::from_str(&pid)?)
}

pub fn write_pid_to_file(path: &PathBuf, pid: u32) -> Result<File, Error> {
    let mut file = File::create(path)?;
    file.write_all(format!("{}\n", pid).as_bytes())?;
    file.sync_all()?;
    Ok(file)
}

pub fn pid_name_matches_client(sys: &mut impl SystemProcess, pidfile_value: Pid) -> Result<bool, Error> {
    let client_pid = Pid::from_u32(process::id());
    Ok(sys.process_name(client_pid)? == sys.process_name(pidfile_value)?)
}

pub fn try_create_pid_file_with_path(path: PathBuf, sys: &mut impl SystemProcess) -> Result<File, Error> {
    if path.exists() {
        let pid = get_pid_from_file(&path)?;

        if sys.refresh_process(pid) {
            match pid_name_matches_client(sys, pid) {
                Ok(true) => return Err(Error::ServiceAlreadyRunning(pid.to_string())),
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
            path.clone()
                .into_os_string()
                .into_string()
                .map_err(|_| Error::OsStringError)?,
        );
    }

    tracing::info!(
        "Creating PID file at: {}",
        path.clone()
            .into_os_string()
            .into_string()
            .map_err(|_| Error::OsStringError)?,
    );
    write_pid_to_file(&path, process::id())
}

pub fn remove_pid_file(spec_name: String, account_id: String) -> Result<(), Error> {
    let path = pid_file_path(spec_name, account_id);
    tracing::info!(
        "Removing PID file at: {}",
        path.clone()
            .into_os_string()
            .into_string()
            .map_err(|_| Error::OsStringError)?,
    );
    Ok(fs::remove_file(path)?)
}

#[cfg(all(test, feature = "parachain-metadata-kintsugi-testnet"))]
mod tests {
    use super::*;
    use sysinfo::Pid;
    use tempdir::TempDir;

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
    fn test_create_pid_file() {
        let dir_path = TempDir::new("process-tests").unwrap();
        let file_path = &dir_path.path().join("file.pid");
        let mut sys = MockSystem::default();
        assert_eq!(file_path.exists(), false);
        try_create_pid_file_with_path(file_path.clone(), &mut sys).unwrap();
        assert_eq!(file_path.exists(), true);
    }

    #[test]
    fn test_overwrite_stale_pid_file() {
        let dir_path = TempDir::new("process-tests").unwrap();
        let file_path = &dir_path.path().join("file.pid");
        // Some high pid value. PIDs are stored as i32.
        write_pid_to_file(file_path, i32::MAX as u32).unwrap();
        let initial_pid = get_pid_from_file(&file_path).unwrap();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().once().return_const(false);
        try_create_pid_file_with_path(file_path.clone(), &mut sys).unwrap();
        let final_pid = get_pid_from_file(&file_path).unwrap();
        assert_ne!(initial_pid, final_pid);
    }

    #[test]
    fn test_pid_file_with_same_process() {
        let dir_path = TempDir::new("process-tests").unwrap();
        let file_path = &dir_path.path().join("file.pid");
        write_pid_to_file(file_path, process::id()).unwrap();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().once().return_const(true);
        let own_pid = Pid::from_u32(process::id());
        sys.expect_process_name()
            .times(2)
            .returning(|_| Ok("vault".to_string()));

        #[allow(unused_variables)]
        let own_pid_string = own_pid.to_string();
        assert_err!(
            try_create_pid_file_with_path(file_path.clone(), &mut sys),
            #[allow(unused_variables)]
            Err(Error::ServiceAlreadyRunning(own_pid_string))
        );
    }

    #[test]
    fn test_pid_file_overwrite_does_not_fail_when_process_is_killed() {
        let dir_path = TempDir::new("process-tests").unwrap();
        let file_path = &dir_path.path().join("file.pid");
        // Some high pid value. PIDs are stored as i32.
        write_pid_to_file(file_path, i32::MAX as u32).unwrap();
        let mut sys = MockSystem::default();
        sys.expect_refresh_process().once().return_const(true);
        let own_pid = process::id();
        sys.expect_process_name().returning(move |pid| {
            if pid == Pid::from_u32(own_pid) {
                Ok("vault".to_string())
            } else {
                Err(Error::ProcessNotFound(pid.to_string()))
            }
        });
        try_create_pid_file_with_path(file_path.clone(), &mut sys).unwrap();
    }
}
