use std::str::FromStr;

#[derive(Clone, Debug)]
pub enum RestartPolicy {
    Never,
    Always,
}

impl FromStr for RestartPolicy {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "never" => Ok(RestartPolicy::Never),
            "always" => Ok(RestartPolicy::Always),
            _ => Err("Could not parse input as RestartPolicy".to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum LoggingFormat {
    Full,
    Json,
}

impl Default for LoggingFormat {
    fn default() -> Self {
        LoggingFormat::Full
    }
}

impl FromStr for LoggingFormat {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "full" => Ok(LoggingFormat::Full),
            "json" => Ok(LoggingFormat::Json),
            _ => Err("Could not parse input as LoggingFormat".to_string()),
        }
    }
}

impl LoggingFormat {
    pub fn init_subscriber(&self) {
        match *self {
            Self::Full => crate::log::init_subscriber(),
            Self::Json => crate::log::init_json_subscriber(),
        }
    }
}
