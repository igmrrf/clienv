use anyhow::{anyhow, Result};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

use crate::wallet::{derive_key, set_private_file_permissions};

lazy_static! {
    static ref ENV_VARS: Mutex<HashMap<String, String>> = Mutex::new(load_env_variables());
}

#[allow(dead_code)]
pub fn load_env_variables() -> HashMap<String, String> {
    if let Ok(data) = fs::read_to_string("env_vars.json") {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

fn save_env_variables(env_vars: &HashMap<String, String>) {
    if let Ok(data) = serde_json::to_string_pretty(env_vars) {
        let _ = fs::write("env_vars.json", data);
        set_private_file_permissions(std::path::Path::new("env_vars.json"));
    }
}

pub fn get_env_variable(key: &str, encryption_key: &str) -> Option<String> {
    let env_vars = ENV_VARS.lock().unwrap();
    env_vars.get(key).and_then(|v| decrypt(v, encryption_key).ok())
}

pub fn set_env_variable(key: &str, value: &str, encryption_key: &str) {
    let mut env_vars = ENV_VARS.lock().unwrap();
    if let Ok(encrypted_val) = encrypt(value, encryption_key) {
        env_vars.insert(key.to_string(), encrypted_val);
        save_env_variables(&env_vars);
    }
}

pub fn encrypt(plaintext: &str, key: &str) -> Result<String> {
    let k = derive_key(key);
    let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| anyhow!("Cipher init failed"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))?;
    Ok(format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    ))
}

pub fn decrypt(cipher_text: &str, key: &str) -> Result<String> {
    let k = derive_key(key);
    let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| anyhow!("Cipher init failed"))?;
    let parts: Vec<&str> = cipher_text.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid cipher format"));
    }
    let decoded_nonce = BASE64_STANDARD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid nonce"))?;
    let nonce = Nonce::from_slice(&decoded_nonce);
    let cipher_bytes = BASE64_STANDARD
        .decode(parts[1])
        .map_err(|_| anyhow!("Invalid cipher text"))?;
    let plaintext = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|_| anyhow!("Decryption failed"))?;
    String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
}
