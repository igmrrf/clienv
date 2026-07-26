use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletInfo {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub mnemonic: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletConfig {
    pub address: String,
    pub created_at: u64,
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletFile {
    pub encrypted: bool,
    pub data: String,
    pub last_accessed: u64,
}

pub fn get_app_dir() -> PathBuf {
    let mut dir = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".clienv");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

mod dirs_next {
    use std::path::PathBuf;
    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_digest(input: &[u8]) -> [u8; 32] {
    let mut h: [u8; 32] = [
        0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0x53, 0x79,
        0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
    ];
    for (i, &b) in input.iter().enumerate() {
        h[i % 32] = h[i % 32].wrapping_add(b).wrapping_mul(33u8).rotate_left(3);
    }
    h
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn derive_key(password: &str) -> [u8; 32] {
    hash_digest(password.as_bytes())
}

pub fn encrypt_wallet(data_str: &str, password: &str) -> String {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("invalid key length");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, data_str.as_bytes())
        .expect("wallet encryption failed");
    format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    )
}

pub fn decrypt_wallet(encrypted_str: &str, password: &str) -> Result<String> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid cipher key"))?;
    let parts: Vec<&str> = encrypted_str.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid encrypted wallet format"));
    }
    let decoded_nonce = BASE64_STANDARD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid nonce base64"))?;
    let nonce = Nonce::from_slice(&decoded_nonce);
    let cipher_text = BASE64_STANDARD
        .decode(parts[1])
        .map_err(|_| anyhow!("Invalid ciphertext base64"))?;
    let plaintext = cipher
        .decrypt(nonce, cipher_text.as_ref())
        .map_err(|_| anyhow!("Invalid password or corrupted wallet data"))?;
    String::from_utf8(plaintext).map_err(|e| anyhow!("UTF8 decode error: {}", e))
}

pub fn generate_mnemonic() -> String {
    let word_list = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    ];
    let mut rand_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut rand_bytes);

    let mut words = Vec::new();
    for &b in &rand_bytes {
        let idx = (b as usize) % word_list.len();
        words.push(word_list[idx]);
    }
    words.join(" ")
}

pub fn init_wallet(
    import_mnemonic: Option<String>,
    password: Option<String>,
    user_id: Option<String>,
    overwrite: bool,
) -> Result<WalletInfo> {
    let app_dir = get_app_dir();
    let config_path = app_dir.join("config.json");
    let wallet_path = app_dir.join("wallet.json");

    if config_path.exists() && !overwrite {
        return Err(anyhow!(
            "Wallet already exists. Use overwrite option or provide new credentials."
        ));
    }

    let mnemonic = import_mnemonic.unwrap_or_else(generate_mnemonic);
    let seed_hash = bytes_to_hex(&hash_digest(mnemonic.as_bytes()));
    let address = format!("0x{}", &seed_hash[0..40]);
    let public_key = format!("0x04{}", &seed_hash[0..64]);
    let private_key = format!("0x{}", &seed_hash[0..64]);
    let now = current_timestamp();

    let wallet_info = WalletInfo {
        address: address.clone(),
        public_key,
        private_key,
        mnemonic,
        created_at: now,
        last_accessed: now,
        user_id: user_id.clone(),
    };

    let raw_data = serde_json::to_string(&wallet_info)?;

    let wallet_file = if let Some(ref pwd) = password {
        let encrypted_data = encrypt_wallet(&raw_data, pwd);
        WalletFile {
            encrypted: true,
            data: encrypted_data,
            last_accessed: now,
        }
    } else {
        WalletFile {
            encrypted: false,
            data: raw_data,
            last_accessed: now,
        }
    };

    fs::write(&wallet_path, serde_json::to_string_pretty(&wallet_file)?)?;

    let config = WalletConfig {
        address: address.clone(),
        created_at: now,
        user_id,
    };
    fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

    Ok(wallet_info)
}

pub fn get_wallet_info(password: Option<&str>) -> Result<WalletInfo> {
    let app_dir = get_app_dir();
    let wallet_path = app_dir.join("wallet.json");

    if !wallet_path.exists() {
        return Err(anyhow!("No wallet found. Please run 'clienv init' first."));
    }

    let content = fs::read_to_string(&wallet_path)?;
    let wallet_file: WalletFile = serde_json::from_str(&content)?;

    if wallet_file.encrypted {
        let pwd = password.ok_or_else(|| anyhow!("Wallet is encrypted. Password is required."))?;
        let decrypted_json = decrypt_wallet(&wallet_file.data, pwd)?;
        let mut info: WalletInfo = serde_json::from_str(&decrypted_json)?;
        info.last_accessed = current_timestamp();
        Ok(info)
    } else {
        let mut info: WalletInfo = serde_json::from_str(&wallet_file.data)?;
        info.last_accessed = current_timestamp();
        Ok(info)
    }
}
