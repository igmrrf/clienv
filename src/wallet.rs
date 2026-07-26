use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::prelude::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize)]
#[zeroize(drop)]
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
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".bsec");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn set_private_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

pub fn write_secure_file(path: &Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, content)?;
    }
    set_private_file_permissions(path);
    Ok(())
}


pub fn hash_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    if hex.len() % 2 != 0 {
        return Err(anyhow!("Invalid hex length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow!("Invalid hex byte: {}", e)))
        .collect()
}

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    if argon2.hash_password_into(password.as_bytes(), salt, &mut key).is_err() {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        key = hasher.finalize().into();
    }
    key
}

pub fn derive_key_legacy(password: &str) -> [u8; 32] {
    let salt = b"bsec_crypto_salt_v1";
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let mut key: [u8; 32] = hasher.finalize().into();
    for _ in 0..10_000 {
        let mut h = Sha256::new();
        h.update(&key);
        h.update(password.as_bytes());
        key = h.finalize().into();
    }
    key
}

pub fn encrypt_wallet(data_str: &str, password: &str) -> String {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("invalid key length");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, data_str.as_bytes())
        .expect("wallet encryption failed");
    format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    )
}

pub fn decrypt_wallet(encrypted_str: &str, password: &str) -> Result<String> {
    let parts: Vec<&str> = encrypted_str.split(':').collect();
    if parts.len() == 3 {
        let salt = BASE64_STANDARD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid salt base64"))?;
        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid cipher key"))?;
        let decoded_nonce = BASE64_STANDARD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid nonce base64"))?;
        let nonce = Nonce::from_slice(&decoded_nonce);
        let cipher_text = BASE64_STANDARD
            .decode(parts[2])
            .map_err(|_| anyhow!("Invalid ciphertext base64"))?;
        let plaintext = cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(|_| anyhow!("Invalid password or corrupted wallet data"))?;
        String::from_utf8(plaintext).map_err(|e| anyhow!("UTF8 decode error: {}", e))
    } else if parts.len() == 2 {
        let key = derive_key_legacy(password);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid cipher key"))?;
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
    } else {
        Err(anyhow!("Invalid encrypted wallet format"))
    }
}

pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("mnemonic generation failed");
    mnemonic.to_string()
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

    let mnemonic_str = match import_mnemonic {
        Some(m) => {
            let _parsed = bip39::Mnemonic::parse(&m)
                .map_err(|e| anyhow!("Invalid BIP-39 mnemonic phrase: {}", e))?;
            m
        }
        None => generate_mnemonic(),
    };

    let parsed_mnemonic = bip39::Mnemonic::parse(&mnemonic_str)
        .map_err(|e| anyhow!("Failed to parse mnemonic: {}", e))?;
    let seed = parsed_mnemonic.to_seed("");

    let secret_key = k256::SecretKey::from_slice(&seed[0..32])
        .map_err(|e| anyhow!("Failed to derive Secp256k1 secret key: {}", e))?;
    let public_key = secret_key.public_key();

    let priv_bytes = secret_key.to_bytes();
    let pub_bytes = public_key.to_encoded_point(false);

    let private_key = format!("0x{}", bytes_to_hex(&priv_bytes));
    let public_key_str = format!("0x{}", bytes_to_hex(pub_bytes.as_bytes()));

    let uncompressed_pub = &pub_bytes.as_bytes()[1..];
    let pub_hash = hash_digest(uncompressed_pub);
    let address = format!("0x{}", bytes_to_hex(&pub_hash[12..32]));
    let now = current_timestamp();

    let wallet_info = WalletInfo {
        address: address.clone(),
        public_key: public_key_str,
        private_key,
        mnemonic: mnemonic_str,
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

    write_secure_file(&wallet_path, serde_json::to_string_pretty(&wallet_file)?.as_bytes())?;

    let config = WalletConfig {
        address: address.clone(),
        created_at: now,
        user_id,
    };
    write_secure_file(&config_path, serde_json::to_string_pretty(&config)?.as_bytes())?;

    Ok(wallet_info)
}

pub fn get_wallet_info(password: Option<&str>) -> Result<WalletInfo> {
    let app_dir = get_app_dir();
    let wallet_path = app_dir.join("wallet.json");

    if !wallet_path.exists() {
        return Err(anyhow!("No wallet found. Please run 'bsec init' first."));
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
