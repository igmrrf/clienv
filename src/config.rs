use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub encryption_key: String,
}

impl Default for Config {
    fn default() -> Self {
        let key = env::var("ENCRYPTION_KEY").unwrap_or_else(|_| {
            let app_dir = crate::wallet::get_app_dir();
            let key_path = app_dir.join(".master_key");
            if let Ok(k) = fs::read_to_string(&key_path)
                && !k.trim().is_empty() {
                    return k.trim().to_string();
            }
            let mut rand_bytes = [0u8; 32];
            aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, &mut rand_bytes);
            let gen_key = crate::wallet::bytes_to_hex(&rand_bytes);
            // FAILSAFE DESIGN: Attempt to persist generated master key to disk. If writing fails (e.g. read-only filesystem),
            // log an error warning and proceed with the in-memory key as a failsafe so execution is not blocked.
            if let Err(e) = crate::wallet::write_secure_file(&key_path, gen_key.as_bytes()) {
                log::warn!("Failed to persist master key to {}: {}", key_path.display(), e);
            }
            gen_key
        });
        Self {
            encryption_key: key,
        }
    }
}

pub fn get_config() -> Config {
    Config::default()
}
