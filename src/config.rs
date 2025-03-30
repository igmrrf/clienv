use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub encryption_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            encryption_key: env::var("ENCRYPTION_KEY")
                .unwrap_or_else(|_| "default_encryption_key".into()),
        }
    }
}

pub fn get_config() -> Config {
    confy::load("clienv", "clienv").unwrap_or_default()
}
