use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::wallet::{bytes_to_hex, hash_digest, hex_to_bytes, set_private_file_permissions};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRecord {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub content: String,
    pub content_key: String,
    pub ephemeral_pubkey: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_reads: u32,
    pub read_count: u32,
    pub hidden: bool,
}

pub fn parse_duration(ttl_str: &str) -> Result<u64> {
    let ttl_str = ttl_str.trim();
    if ttl_str.is_empty() {
        return Ok(86400 * 7);
    }
    let (num_part, unit) = ttl_str.split_at(ttl_str.len() - 1);
    let val: u64 = num_part
        .parse()
        .map_err(|_| anyhow!("Invalid TTL number format"))?;
    match unit {
        "s" => Ok(val),
        "m" => Ok(val * 60),
        "h" => Ok(val * 3600),
        "d" => Ok(val * 86400),
        _ => {
            if let Ok(full_val) = ttl_str.parse::<u64>() {
                Ok(full_val)
            } else {
                Err(anyhow!("Invalid TTL unit (use s, m, h, d)"))
            }
        }
    }
}

pub fn get_secrets_dir() -> PathBuf {
    let dir = crate::wallet::get_app_dir().join("secrets");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

fn encrypt_text(plain: &str, key_bytes: &[u8; 32]) -> String {
    let cipher = Aes256Gcm::new_from_slice(key_bytes).expect("key init failed");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, plain.as_bytes())
        .expect("encryption failed");
    format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    )
}

fn decrypt_text(cipher_str: &str, key_bytes: &[u8; 32]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|_| anyhow!("key init failed"))?;
    let parts: Vec<&str> = cipher_str.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid cipher format"));
    }
    let nonce_bytes = BASE64_STANDARD
        .decode(parts[0])
        .map_err(|_| anyhow!("nonce decode failed"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher_bytes = BASE64_STANDARD
        .decode(parts[1])
        .map_err(|_| anyhow!("cipher decode failed"))?;
    let plain_bytes = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|_| anyhow!("decryption failed"))?;
    String::from_utf8(plain_bytes).map_err(|e| anyhow!("utf8 error: {}", e))
}

fn resolve_recipient_pubkey(to_address: &str, sender_info: &crate::wallet::WalletInfo) -> Result<PublicKey> {
    if to_address == sender_info.address || to_address == sender_info.public_key || to_address == "public" {
        let pub_bytes = hex_to_bytes(&sender_info.public_key)?;
        return PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow!("Invalid sender public key: {}", e));
    }

    if to_address.starts_with("0x04") || to_address.starts_with("04") || to_address.starts_with("0x02") || to_address.starts_with("0x03") {
        let pub_bytes = hex_to_bytes(to_address)?;
        return PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow!("Invalid recipient public key: {}", e));
    }

    Err(anyhow!(
        "Recipient must be a valid SEC1 public key (starting with 0x04, 0x02, or 0x03), 'public', or your wallet address."
    ))
}

pub fn share_secret(
    content: &str,
    ttl_str: &str,
    max_reads: u32,
    to_address: &str,
    sender_address: &str,
) -> Result<SecretRecord> {
    let ttl_secs = parse_duration(ttl_str)?;
    let now = crate::wallet::current_timestamp();
    let expires_at = now + ttl_secs;

    let sender_info = crate::wallet::get_wallet_info(None)?;
    let recipient_pubkey = resolve_recipient_pubkey(to_address, &sender_info)?;

    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();
    let shared_secret = k256::ecdh::diffie_hellman(
        ephemeral_secret.to_nonzero_scalar(),
        recipient_pubkey.as_affine(),
    );
    let wrapper_key = hash_digest(shared_secret.raw_secret_bytes());

    let mut random_content_key = [0u8; 32];
    OsRng.fill_bytes(&mut random_content_key);

    let encrypted_content = encrypt_text(content, &random_content_key);
    let encrypted_content_key = encrypt_text(&BASE64_STANDARD.encode(&random_content_key), &wrapper_key);

    let id_seed = format!("{}:{}:{}", sender_address, to_address, now);
    let id_hash = bytes_to_hex(&hash_digest(id_seed.as_bytes()));
    let secret_id = id_hash[0..16].to_string();

    let ephemeral_pub_hex = format!("0x{}", bytes_to_hex(ephemeral_public.to_encoded_point(false).as_bytes()));

    let record = SecretRecord {
        id: secret_id.clone(),
        sender: sender_address.to_string(),
        recipient: to_address.to_string(),
        content: encrypted_content,
        content_key: encrypted_content_key,
        ephemeral_pubkey: Some(ephemeral_pub_hex),
        created_at: now,
        expires_at,
        max_reads,
        read_count: 0,
        hidden: false,
    };

    let path = get_secrets_dir().join(format!("{}.json", secret_id));
    fs::write(&path, serde_json::to_string_pretty(&record)?)?;
    set_private_file_permissions(&path);

    Ok(record)
}

pub fn view_secret(secret_id: &str, user_address: &str) -> Result<String> {
    let path = get_secrets_dir().join(format!("{}.json", secret_id));
    if !path.exists() {
        return Err(anyhow!("Secret with ID '{}' not found.", secret_id));
    }

    let file_content = fs::read_to_string(&path)?;
    let mut record: SecretRecord = serde_json::from_str(&file_content)?;

    if record.recipient != user_address && record.sender != user_address {
        return Err(anyhow!("You do not have permission to view this secret."));
    }

    let now = crate::wallet::current_timestamp();
    if now > record.expires_at {
        let _ = fs::remove_file(&path);
        return Err(anyhow!("This secret has expired."));
    }

    if record.read_count >= record.max_reads {
        let _ = fs::remove_file(&path);
        return Err(anyhow!("Maximum read count exceeded for this secret."));
    }

    let wallet_info = crate::wallet::get_wallet_info(None)?;
    let wrapper_key = if let Some(ref eph_hex) = record.ephemeral_pubkey {
        let eph_bytes = hex_to_bytes(eph_hex)?;
        let eph_public = PublicKey::from_sec1_bytes(&eph_bytes)
            .map_err(|e| anyhow!("Invalid ephemeral public key: {}", e))?;

        let priv_bytes = hex_to_bytes(&wallet_info.private_key)?;
        let secret_key = SecretKey::from_slice(&priv_bytes)
            .map_err(|e| anyhow!("Invalid wallet private key: {}", e))?;

        let shared_secret = k256::ecdh::diffie_hellman(
            secret_key.to_nonzero_scalar(),
            eph_public.as_affine(),
        );
        hash_digest(shared_secret.raw_secret_bytes())
    } else {
        hash_digest(format!("bsec_wrapper_key:{}", record.recipient).as_bytes())
    };

    let decrypted_content_key_b64 = decrypt_text(&record.content_key, &wrapper_key)
        .map_err(|_| anyhow!("Failed to decrypt content key for secret"))?;

    let key_bytes_vec = BASE64_STANDARD
        .decode(&decrypted_content_key_b64)
        .map_err(|_| anyhow!("Failed to decode content key"))?;
    let mut key_bytes = [0u8; 32];
    if key_bytes_vec.len() != 32 {
        return Err(anyhow!("Invalid content key length"));
    }
    key_bytes.copy_from_slice(&key_bytes_vec);

    let decrypted = decrypt_text(&record.content, &key_bytes)?;

    record.read_count += 1;

    if record.read_count >= record.max_reads {
        let _ = fs::remove_file(&path);
    } else {
        let _ = fs::write(&path, serde_json::to_string_pretty(&record)?);
        set_private_file_permissions(&path);
    }

    Ok(decrypted)
}

pub fn load_secret_as_env(secret_id: &str, user_address: &str) -> Result<BTreeMap<String, String>> {
    let decrypted_content = view_secret(secret_id, user_address)?;
    if decrypted_content.trim().starts_with('{') {
        crate::env_file::parse_json_content(&decrypted_content)
    } else {
        Ok(crate::env_file::parse_env_content(&decrypted_content))
    }
}

pub fn list_secrets(
    user_address: &str,
    filter_user: Option<&str>,
    all: bool,
    expired_only: bool,
    active_only: bool,
) -> Result<Vec<SecretRecord>> {
    let dir = get_secrets_dir();
    let entries = fs::read_dir(dir)?;
    let now = crate::wallet::current_timestamp();
    let mut results = Vec::new();

    for entry in entries.flatten() {
        if entry.path().extension().map_or(false, |ext| ext == "json") {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(record) = serde_json::from_str::<SecretRecord>(&content) {
                    if record.hidden {
                        continue;
                    }

                    if let Some(target) = filter_user {
                        if record.recipient != target && record.sender != target {
                            continue;
                        }
                    } else if !all && record.sender != user_address && record.recipient != user_address {
                        continue;
                    }

                    let is_expired = now > record.expires_at || record.read_count >= record.max_reads;

                    if expired_only && !is_expired {
                        continue;
                    }
                    if active_only && is_expired {
                        continue;
                    }

                    results.push(record);
                }
            }
        }
    }

    Ok(results)
}

pub fn revoke_secret(secret_id: &str, user_address: &str) -> Result<()> {
    let path = get_secrets_dir().join(format!("{}.json", secret_id));
    if !path.exists() {
        return Err(anyhow!("Secret with ID '{}' not found.", secret_id));
    }

    let file_content = fs::read_to_string(&path)?;
    let record: SecretRecord = serde_json::from_str(&file_content)?;

    if record.sender != user_address {
        return Err(anyhow!("You can only revoke secrets that you have created."));
    }

    fs::remove_file(&path)?;
    Ok(())
}

pub fn hide_secret(secret_id: Option<&str>, user_filter: Option<&str>, user_address: &str) -> Result<usize> {
    let dir = get_secrets_dir();
    let entries = fs::read_dir(dir)?;
    let mut hidden_count = 0;

    for entry in entries.flatten() {
        if entry.path().extension().map_or(false, |ext| ext == "json") {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(mut record) = serde_json::from_str::<SecretRecord>(&content) {
                    let mut should_hide = false;
                    if let Some(target_id) = secret_id {
                        if record.id == target_id {
                            should_hide = true;
                        }
                    }
                    if let Some(target_user) = user_filter {
                        if record.recipient == target_user || record.sender == target_user {
                            should_hide = true;
                        }
                    }
                    if secret_id.is_none() && user_filter.is_none() {
                        if record.sender == user_address || record.recipient == user_address {
                            should_hide = true;
                        }
                    }

                    if should_hide {
                        record.hidden = true;
                        let _ = fs::write(entry.path(), serde_json::to_string_pretty(&record)?);
                        set_private_file_permissions(&entry.path());
                        hidden_count += 1;
                    }
                }
            }
        }
    }

    Ok(hidden_count)
}
