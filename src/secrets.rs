use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRecord {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub content: String,
    pub content_key: String,
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

    let mut random_key = [0u8; 32];
    OsRng.fill_bytes(&mut random_key);

    let encrypted_content = encrypt_text(content, &random_key);
    let content_key_b64 = BASE64_STANDARD.encode(&random_key);

    let id_seed = format!("{}:{}:{}", sender_address, to_address, now);
    let id_hash = bytes_to_hex(&hash_digest(id_seed.as_bytes()));
    let secret_id = id_hash[0..16].to_string();

    let record = SecretRecord {
        id: secret_id.clone(),
        sender: sender_address.to_string(),
        recipient: to_address.to_string(),
        content: encrypted_content,
        content_key: content_key_b64,
        created_at: now,
        expires_at,
        max_reads,
        read_count: 0,
        hidden: false,
    };

    let path = get_secrets_dir().join(format!("{}.json", secret_id));
    fs::write(&path, serde_json::to_string_pretty(&record)?)?;

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

    record.read_count += 1;

    let key_bytes_vec = BASE64_STANDARD
        .decode(&record.content_key)
        .map_err(|_| anyhow!("Failed to decode content key"))?;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&key_bytes_vec);

    let decrypted = decrypt_text(&record.content, &key_bytes)?;

    if record.read_count >= record.max_reads {
        let _ = fs::remove_file(&path);
    } else {
        let _ = fs::write(&path, serde_json::to_string_pretty(&record)?);
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
                        hidden_count += 1;
                    }
                }
            }
        }
    }

    Ok(hidden_count)
}
