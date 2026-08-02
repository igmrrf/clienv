use anyhow::{anyhow, Result};
use crate::errors::BsecError;
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
use zeroize::{Zeroize, Zeroizing};

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
pub struct WalletInfoPublic {
    pub address: String,
    pub public_key: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub user_id: Option<String>,
}

impl From<&WalletInfo> for WalletInfoPublic {
    fn from(w: &WalletInfo) -> Self {
        Self {
            address: w.address.clone(),
            public_key: w.public_key.clone(),
            created_at: w.created_at,
            last_accessed: w.last_accessed,
            user_id: w.user_id.clone(),
        }
    }
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
    if let Ok(bsec_home) = std::env::var("BSEC_HOME") {
        let path = PathBuf::from(bsec_home);
        if !path.exists() {
            let _ = fs::create_dir_all(&path);
        }
        return path;
    }
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
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("Invalid hex length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow!("Invalid hex byte: {}", e)))
        .collect()
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    let effective_salt = if salt.len() < 8 {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.finalize().to_vec()
    } else {
        salt.to_vec()
    };
    argon2
        .hash_password_into(password.as_bytes(), &effective_salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}

pub fn derive_key_legacy(password: &str) -> [u8; 32] {
    let salt = b"bsec_crypto_salt_v1";
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let mut key: [u8; 32] = hasher.finalize().into();
    for _ in 0..10_000 {
        let mut h = Sha256::new();
        h.update(key);
        h.update(password.as_bytes());
        key = h.finalize().into();
    }
    key
}

pub fn encrypt_wallet(data_str: &str, password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid cipher key length"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, data_str.as_bytes())
        .map_err(|_| anyhow!("wallet encryption failed"))?;
    Ok(format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    ))
}

pub fn decrypt_wallet(encrypted_str: &str, password: &str) -> Result<String> {
    let parts: Vec<&str> = encrypted_str.split(':').collect();
    if parts.len() == 3 {
        let salt = BASE64_STANDARD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid salt base64"))?;
        let key = derive_key(password, &salt)?;
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
            .map_err(|_| BsecError::InvalidPassword)?;
        let text_str = String::from_utf8(plaintext).map_err(|e| anyhow!("UTF8 decode error: {}", e))?;
        Ok(text_str)
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
            .map_err(|_| BsecError::InvalidPassword)?;
        let text_str = String::from_utf8(plaintext).map_err(|e| anyhow!("UTF8 decode error: {}", e))?;
        Ok(text_str)
    } else {
        Err(anyhow!("Invalid encrypted wallet format"))
    }
}

pub fn generate_mnemonic() -> Result<String> {
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| anyhow!("mnemonic generation failed: {}", e))?;
    Ok(mnemonic.to_string())
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
                .map_err(|e| BsecError::InvalidMnemonic(e.to_string()))?;
            m
        }
        None => generate_mnemonic()?,
    };

    let parsed_mnemonic = bip39::Mnemonic::parse(&mnemonic_str)
        .map_err(|e| anyhow!("Failed to parse mnemonic: {}", e))?;
    let seed = parsed_mnemonic.to_seed("");

    // Standard BIP-44 Ethereum path. Any derivation failure is a hard error: silently
    // falling back to a raw seed slice would produce a DIFFERENT (non-standard) key/address
    // than the mnemonic implies, stranding funds and making secrets un-decryptable.
    let derivation_path = "m/44'/60'/0'/0/0";
    let path = derivation_path
        .parse::<bip32::DerivationPath>()
        .map_err(|e| anyhow!("Invalid derivation path '{}': {}", derivation_path, e))?;
    let xprv = bip32::XPrv::derive_from_path(seed, &path)
        .map_err(|e| anyhow!("BIP-32 HD key derivation failed for path {}: {}", derivation_path, e))?;
    let secret_key = k256::SecretKey::from_slice(&xprv.private_key().to_bytes())
        .map_err(|e| anyhow!("Failed to derive secp256k1 key: {}", e))?;

    let public_key = secret_key.public_key();

    let priv_bytes = secret_key.to_bytes();
    let pub_bytes = public_key.to_encoded_point(false);

    let private_key = format!("0x{}", bytes_to_hex(&priv_bytes));
    let public_key_str = format!("0x{}", bytes_to_hex(pub_bytes.as_bytes()));

    let uncompressed_pub = &pub_bytes.as_bytes()[1..];
    let pub_hash = crate::blockchain::keccak256(uncompressed_pub);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&pub_hash[12..32]);
    let address = crate::blockchain::bytes_to_checksum_address(&addr_bytes);
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

    // Zeroizing: the serialized blob contains the plaintext private key and mnemonic. Wiping it
    // after use keeps the encrypted path from leaving the plaintext lingering in freed memory.
    let raw_data = Zeroizing::new(serde_json::to_string(&wallet_info)?);

    let wallet_file = if let Some(ref pwd) = password {
        let encrypted_data = encrypt_wallet(raw_data.as_str(), pwd)?;
        WalletFile {
            encrypted: true,
            data: encrypted_data,
            last_accessed: now,
        }
    } else {
        eprintln!(
            "WARNING: wallet created WITHOUT a password. The private key and mnemonic are stored \
             UNENCRYPTED at {}. Anyone with read access to this file controls the wallet. \
             Re-run with --password to encrypt it.",
            wallet_path.display()
        );
        WalletFile {
            encrypted: false,
            data: raw_data.as_str().to_string(),
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
        return Err(BsecError::WalletNotFound.into());
    }

    let content = fs::read_to_string(&wallet_path)?;
    let wallet_file: WalletFile = serde_json::from_str(&content)?;

    // Read-only: do NOT rewrite wallet.json here. The previous write-on-read updated
    // `last_accessed` on every read, which raced under concurrent invocations (unsynchronized
    // read-modify-write) and rewrote the plaintext key for unencrypted wallets. The marginal
    // value of a read timestamp does not justify either hazard.
    let info = if wallet_file.encrypted {
        let pwd = password.ok_or_else(|| anyhow!("Wallet is encrypted. Password is required."))?;
        let decrypted_json = Zeroizing::new(decrypt_wallet(&wallet_file.data, pwd)?);
        serde_json::from_str::<WalletInfo>(&decrypted_json)?
    } else {
        serde_json::from_str::<WalletInfo>(&wallet_file.data)?
    };

    Ok(info)
}
