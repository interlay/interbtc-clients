use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    process,
    str::FromStr,
};

use service::Error;
use sysinfo::{Pid, System, SystemExt};

pub fn pid_file_path(spec_name: String, account_id: String) -> PathBuf {
    let file_name = format!("{}_{}.pid", spec_name, account_id);
    // Use the default temporary directory of the OS
    let mut path = std::env::temp_dir();
    path.push(file_name);
    path
}

pub fn try_create_pid_file(spec_name: String, account_id: String, sys: &mut System) -> Result<File, Error> {
    let path = pid_file_path(spec_name, account_id);
    if path.exists() {
        let mut pid = fs::read_to_string(path.clone())?;
        pid = pid.strip_suffix("\n").unwrap_or(&pid).to_string();

        print!("{}", pid);
        if sys.refresh_process(Pid::from_str(&pid)?) {
            return Err(Error::ServiceAlreadyRunning(pid));
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
    let mut file = OpenOptions::new().read(true).write(true).create(true).open(path)?;

    file.write_all(format!("{}\n", process::id()).as_bytes())?;
    Ok(file)
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
