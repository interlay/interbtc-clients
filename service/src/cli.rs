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
