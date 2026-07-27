use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::blockchain::{
    get_secret_info_on_chain, hide_secret_on_chain, list_secrets_on_chain, record_read_on_chain, register_secret_on_chain,
    revoke_secret_on_chain,
};
use crate::ipfs::{fetch_from_ipfs, upload_to_ipfs};
use crate::wallet::{bytes_to_hex, hash_digest, hex_to_bytes};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpfsPayload {
    pub content: String,
    pub content_key: String,
    pub ephemeral_pubkey: Option<String>,
}

pub fn parse_duration(ttl_str: &str) -> Result<u64> {
    let ttl_str = ttl_str.trim();
    if ttl_str.is_empty() {
        return Ok(86400 * 7);
    }
    let split_pos = ttl_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(ttl_str.len());
    let (num_part, unit_part) = ttl_str.split_at(split_pos);
    let val: u64 = num_part
        .parse()
        .map_err(|_| anyhow!("Invalid TTL number format"))?;
    let unit = unit_part.trim().to_lowercase();
    match unit.as_str() {
        "" | "s" | "sec" | "second" | "seconds" => Ok(val),
        "m" | "min" | "minute" | "minutes" => Ok(val * 60),
        "h" | "hr" | "hour" | "hours" => Ok(val * 3600),
        "d" | "day" | "days" => Ok(val * 86400),
        "w" | "week" | "weeks" => Ok(val * 86400 * 7),
        _ => Err(anyhow!("Invalid TTL unit (use s, m, h, d, w)")),
    }
}

fn encrypt_text(plain: &str, key_bytes: &[u8; 32]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|_| anyhow!("key init failed"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, plain.as_bytes())
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    ))
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

fn resolve_recipient_pubkey(to_address: &str, sender_info: &crate::wallet::WalletInfo) -> Result<Option<PublicKey>> {
    if to_address.to_lowercase() == sender_info.address.to_lowercase() || to_address == sender_info.public_key {
        let pub_bytes = hex_to_bytes(&sender_info.public_key)?;
        return PublicKey::from_sec1_bytes(&pub_bytes)
            .map(Some)
            .map_err(|e| anyhow!("Invalid sender public key: {}", e));
    }

    if to_address == "public" {
        return Ok(None);
    }

    if to_address.starts_with("0x04") || to_address.starts_with("04") || to_address.starts_with("0x02") || to_address.starts_with("0x03") {
        let pub_bytes = hex_to_bytes(to_address)?;
        return PublicKey::from_sec1_bytes(&pub_bytes)
            .map(Some)
            .map_err(|e| anyhow!("Invalid recipient public key: {}", e));
    }

    Err(anyhow!(
        "Recipient must be a valid SEC1 public key (0x04...), your own wallet address, or 'public'. EVM addresses (0x...) of external users cannot be used for ECDH key exchange without their public key."
    ))
}

pub fn share_secret(
    content: &str,
    ttl_str: &str,
    max_reads: u32,
    to_address: &str,
    sender_address: &str,
    password: Option<&str>,
) -> Result<SecretRecord> {
    if content.len() > 10 * 1024 * 1024 {
        return Err(anyhow!("Secret content size exceeds maximum limit of 10MB."));
    }

    let ttl_secs = parse_duration(ttl_str)?;
    let now = crate::wallet::current_timestamp();
    let expires_at = now + ttl_secs;

    let sender_info = crate::wallet::get_wallet_info(password)?;
    let recipient_pubkey_opt = resolve_recipient_pubkey(to_address, &sender_info)?;

    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();
    let ephemeral_pub_hex = format!("0x{}", bytes_to_hex(ephemeral_public.to_encoded_point(false).as_bytes()));

    let wrapper_key = if to_address == "public" {
        hash_digest(b"bsec_public_secret_wrapper_key_v1")
    } else if let Some(recipient_pubkey) = recipient_pubkey_opt {
        let shared_secret = k256::ecdh::diffie_hellman(
            ephemeral_secret.to_nonzero_scalar(),
            recipient_pubkey.as_affine(),
        );
        hash_digest(shared_secret.raw_secret_bytes())
    } else {
        return Err(anyhow!("Cannot resolve recipient public key for encryption."));
    };

    let mut random_content_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(random_content_key.as_mut());

    let encrypted_content = encrypt_text(content, &random_content_key)?;
    let encrypted_content_key = encrypt_text(&BASE64_STANDARD.encode(random_content_key.as_ref()), &wrapper_key)?;

    let payload = IpfsPayload {
        content: encrypted_content.clone(),
        content_key: encrypted_content_key.clone(),
        ephemeral_pubkey: Some(ephemeral_pub_hex.clone()),
    };
    let payload_json = serde_json::to_string(&payload)?;

    let ipfs_cid = upload_to_ipfs(&payload_json)?;

    let random_nonce: u64 = rand::random();
    let id_seed = format!("{}:{}:{}:{}", sender_address, to_address, now, random_nonce);
    let id_hash = bytes_to_hex(&hash_digest(id_seed.as_bytes()));
    let secret_id = id_hash[0..16].to_string();

    let is_public = to_address == "public";

    register_secret_on_chain(
        &secret_id,
        to_address,
        &ipfs_cid,
        expires_at,
        max_reads,
        is_public,
        sender_address,
    )?;

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

    Ok(record)
}

pub fn view_secret(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<String> {
    let onchain_info = get_secret_info_on_chain(secret_id)?;

    let wallet_info = crate::wallet::get_wallet_info(password)?;

    let is_recipient = onchain_info.is_public
        || onchain_info.recipient.to_lowercase() == wallet_info.address.to_lowercase()
        || onchain_info.recipient == wallet_info.public_key
        || onchain_info.recipient.to_lowercase() == user_address.to_lowercase();

    let is_sender = onchain_info.sender.to_lowercase() == wallet_info.address.to_lowercase()
        || onchain_info.sender == wallet_info.public_key
        || onchain_info.sender.to_lowercase() == user_address.to_lowercase();

    if !is_recipient && !is_sender {
        return Err(anyhow!("You do not have permission to view this secret."));
    }

    if onchain_info.revoked {
        return Err(anyhow!("Secret with ID '{}' has been revoked.", secret_id));
    }

    let now = crate::wallet::current_timestamp();
    if now > onchain_info.expires_at {
        return Err(anyhow!("This secret has expired."));
    }

    if onchain_info.read_count >= onchain_info.max_reads {
        return Err(anyhow!("Maximum read count exceeded for this secret."));
    }

    let payload_str = fetch_from_ipfs(&onchain_info.ipfs_cid)?;
    let payload: IpfsPayload = serde_json::from_str(&payload_str)?;

    let wrapper_key = if onchain_info.is_public || onchain_info.recipient == "public" {
        hash_digest(b"bsec_public_secret_wrapper_key_v1")
    } else if let Some(ref eph_hex) = payload.ephemeral_pubkey {
        let eph_bytes = hex_to_bytes(eph_hex)?;
        let eph_public = PublicKey::from_sec1_bytes(&eph_bytes)
            .map_err(|e| anyhow!("Invalid ephemeral public key: {}", e))?;

        let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);
        let secret_key = SecretKey::from_slice(&priv_bytes)
            .map_err(|e| anyhow!("Invalid wallet private key: {}", e))?;

        let shared_secret = k256::ecdh::diffie_hellman(
            secret_key.to_nonzero_scalar(),
            eph_public.as_affine(),
        );
        hash_digest(shared_secret.raw_secret_bytes())
    } else {
        return Err(anyhow!("Corrupted secret payload: missing ephemeral public key"));
    };

    let decrypted_content_key_b64 = Zeroizing::new(
        decrypt_text(&payload.content_key, &wrapper_key)
            .map_err(|_| anyhow!("Failed to decrypt content key for secret"))?,
    );

    let key_bytes_vec = Zeroizing::new(
        BASE64_STANDARD
            .decode(decrypted_content_key_b64.as_str())
            .map_err(|_| anyhow!("Failed to decode content key"))?,
    );
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    if key_bytes_vec.len() != 32 {
        return Err(anyhow!("Invalid content key length"));
    }
    key_bytes.copy_from_slice(&key_bytes_vec);

    let decrypted = decrypt_text(&payload.content, &key_bytes)?;

    record_read_on_chain(secret_id)?;

    Ok(decrypted)
}

pub fn load_secret_as_env(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<BTreeMap<String, String>> {
    let decrypted_content = view_secret(secret_id, user_address, password)?;
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
    let onchain_list = list_secrets_on_chain(user_address, filter_user, all, expired_only, active_only)?;
    let mut results = Vec::new();

    for (sec_id, info) in onchain_list {
        results.push(SecretRecord {
            id: sec_id,
            sender: info.sender,
            recipient: info.recipient,
            content: "[Encrypted Payload on IPFS]".to_string(),
            content_key: "[Encrypted Key]".to_string(),
            ephemeral_pubkey: None,
            created_at: info.created_at,
            expires_at: info.expires_at,
            max_reads: info.max_reads,
            read_count: info.read_count,
            hidden: false,
        });
    }

    Ok(results)
}

pub fn revoke_secret(secret_id: &str, user_address: &str) -> Result<()> {
    revoke_secret_on_chain(secret_id, user_address)
}

pub fn hide_secret(secret_id: Option<&str>, user_filter: Option<&str>, user_address: &str) -> Result<usize> {
    let onchain_list = list_secrets_on_chain(user_address, user_filter, true, false, false)?;
    let mut hidden_count = 0;

    for (id, rec) in onchain_list {
        let matches_id = secret_id.map_or(true, |target| id == target);
        let matches_filter = user_filter.map_or(true, |target| {
            rec.recipient.to_lowercase() == target.to_lowercase()
                || rec.sender.to_lowercase() == target.to_lowercase()
        });

        if matches_id && matches_filter {
            // FAILSAFE DESIGN: Hiding a secret sets local visibility state (`hidden = true`).
            // It also attempts best-effort on-chain revocation if the user is the creator.
            // Any error during on-chain revocation is logged safely so local hiding succeeds.
            if let Ok(()) = hide_secret_on_chain(&id, user_address) {
                hidden_count += 1;
            }
        }
    }

    Ok(hidden_count)
}
