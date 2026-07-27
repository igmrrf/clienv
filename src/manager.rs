use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

use crate::wallet::{derive_key, write_secure_file};

lazy_static! {
    static ref ENV_VARS: Mutex<HashMap<String, String>> = Mutex::new(load_env_variables());
}

fn get_storage_path() -> std::path::PathBuf {
    crate::wallet::get_app_dir().join("env_vars.json")
}

#[allow(dead_code)]
pub fn load_env_variables() -> HashMap<String, String> {
    let path = get_storage_path();
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

fn save_env_variables(env_vars: &HashMap<String, String>) {
    let path = get_storage_path();
    if let Ok(data) = serde_json::to_string_pretty(env_vars) {
        let _ = write_secure_file(&path, data.as_bytes());
    }
}

pub fn get_env_variable(key: &str, encryption_key: &str) -> Option<String> {
    let env_vars = ENV_VARS.lock().unwrap_or_else(|e| e.into_inner());
    env_vars.get(key).and_then(|v| decrypt(v, encryption_key).ok())
}

pub fn set_env_variable(key: &str, value: &str, encryption_key: &str) {
    let mut env_vars = ENV_VARS.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(encrypted_val) = encrypt(value, encryption_key) {
        env_vars.insert(key.to_string(), encrypted_val);
        save_env_variables(&env_vars);
    }
}

pub fn encrypt(plaintext: &str, key: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let k = derive_key(key, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| anyhow!("Cipher init failed"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))?;
    Ok(format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    ))
}

pub fn decrypt(encrypted_str: &str, key: &str) -> Result<String> {
    let parts: Vec<&str> = encrypted_str.split(':').collect();
    if parts.len() == 3 {
        let salt = BASE64_STANDARD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid salt"))?;
        let k = derive_key(key, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| anyhow!("Cipher init failed"))?;
        let nonce_bytes = BASE64_STANDARD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid nonce"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher_bytes = BASE64_STANDARD
            .decode(parts[2])
            .map_err(|_| anyhow!("Invalid cipher text"))?;
        let plaintext = cipher
            .decrypt(nonce, cipher_bytes.as_ref())
            .map_err(|_| anyhow!("Decryption failed"))?;
        String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    } else if parts.len() == 2 {
        let k = derive_key(key, b"bsec_manager_salt")?;
        let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| anyhow!("Cipher init failed"))?;
        let nonce_bytes = BASE64_STANDARD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid nonce"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher_bytes = BASE64_STANDARD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid cipher text"))?;
        let plaintext = cipher
            .decrypt(nonce, cipher_bytes.as_ref())
            .map_err(|_| anyhow!("Decryption failed"))?;
        String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    } else {
        Err(anyhow!("Invalid cipher format"))
    }
}
