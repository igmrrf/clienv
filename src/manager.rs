use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

lazy_static! {
    static ref ENV_VARS: Mutex<HashMap<String, String>> = Mutex::new(load_env_variables());
}

fn load_env_variables() -> HashMap<String, String> {
    if let Ok(data) = fs::read_to_string("env_vars.json") {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

fn save_env_variables(env_vars: &HashMap<String, String>) {
    if let Ok(data) = serde_json::to_string_pretty(env_vars) {
        fs::write("env_vars.json", data).unwrap();
    }
}

pub fn get_env_variable(key: &str, encryption_key: &str) -> Option<String> {
    let env_vars = ENV_VARS.lock().unwrap();
    env_vars.get(key).map(|v| decrypt(v, encryption_key))
}

pub fn set_env_variable(key: &str, value: &str, encryption_key: &str) {
    let mut env_vars = ENV_VARS.lock().unwrap();
    env_vars.insert(key.to_string(), encrypt(value, encryption_key));
    save_env_variables(&env_vars)
}

pub fn encrypt(plaintext: &str, key: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("failed to cipher");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .expect("encryption failed");
    format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    )
}

pub fn decrypt(cipher_text: &str, key: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("failed to cipher");
    let parts: Vec<&str> = cipher_text.split(":").collect();
    let decoded = BASE64_STANDARD.decode(parts[0]).expect("invalid nonce");
    let nonce = Nonce::from_slice(&decoded);
    let cipher_text = BASE64_STANDARD
        .decode(parts[1])
        .expect("invalid cipher_text");
    let plaintext = cipher
        .decrypt(nonce, cipher_text.as_ref())
        .expect("decryption failed");
    String::from_utf8(plaintext).expect("invalid UTF-8 sequence")
}
