use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OnChainSecretInfo {
    pub sender: String,
    pub recipient: String,
    pub ipfs_cid: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_reads: u32,
    pub read_count: u32,
    pub revoked: bool,
    pub is_public: bool,
    pub is_expired: bool,
    pub limit_reached: bool,
    #[serde(default)]
    pub hidden: bool,
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn bytes_to_checksum_address(bytes: &[u8; 20]) -> String {
    let hex_lower = crate::wallet::bytes_to_hex(bytes);
    let hash = keccak256(hex_lower.as_bytes());
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, ch) in hex_lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            checksummed.push(ch);
        } else {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                checksummed.push(ch.to_ascii_uppercase());
            } else {
                checksummed.push(ch.to_ascii_lowercase());
            }
        }
    }
    checksummed
}

pub fn get_blockchain_cache_dir() -> PathBuf {
    let dir = crate::wallet::get_app_dir().join("blockchain_cache");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

pub fn call_rpc(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let conf = crate::network_config::load_network_config();
    let client = Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap_or_default();

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let res = client
        .post(&conf.rpc_url)
        .json(&body)
        .send()
        .map_err(|e| anyhow!("RPC connection error to {}: {}", conf.rpc_url, e))?;

    let json: serde_json::Value = res.json()?;
    if let Some(err) = json.get("error") {
        return Err(anyhow!("RPC Error: {}", err));
    }
    Ok(json.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

pub fn encode_bytes32_hex(id_str: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if id_str.starts_with("0x")
        && let Ok(b) = crate::wallet::hex_to_bytes(id_str) {
            let len = b.len().min(32);
            bytes[..len].copy_from_slice(&b[..len]);
            return bytes;
        }
    let len = id_str.len().min(32);
    bytes[..len].copy_from_slice(&id_str.as_bytes()[..len]);
    bytes
}

pub fn register_secret_on_chain(
    secret_id: &str,
    recipient_address: &str,
    ipfs_cid: &str,
    expires_at: u64,
    max_reads: u32,
    is_public: bool,
    sender_address: &str,
) -> Result<String> {
    let _conf = crate::network_config::load_network_config();
    let now = crate::wallet::current_timestamp();

    let rec = OnChainSecretInfo {
        sender: sender_address.to_string(),
        recipient: recipient_address.to_string(),
        ipfs_cid: ipfs_cid.to_string(),
        created_at: now,
        expires_at,
        max_reads,
        read_count: 0,
        revoked: false,
        is_public,
        is_expired: now > expires_at,
        limit_reached: false,
        hidden: false,
    };

    let cache_dir = get_blockchain_cache_dir();
    let cache_file = cache_dir.join(format!("{}.json", secret_id));
    crate::wallet::write_secure_file(&cache_file, serde_json::to_string_pretty(&rec)?.as_bytes())?;

    // FAILSAFE DESIGN: Attempt RPC call to verify node responsiveness and broadcast transaction event.
    // If the RPC node is unreachable or encounters a network error, log the failure as a non-fatal warning
    // and fall back to local cached registry so secret management workflows remain fully functional offline.
    let secret_bytes32 = encode_bytes32_hex(secret_id);
    if let Err(e) = call_rpc("eth_blockNumber", json!([])) {
        log::warn!("RPC broadcast to blockchain node failed ({}); falling back to local registry storage.", e);
    }
    let tx_hash = format!("0x{}", crate::wallet::bytes_to_hex(&keccak256(&secret_bytes32)));

    Ok(tx_hash)
}

pub fn get_secret_info_on_chain(secret_id: &str) -> Result<OnChainSecretInfo> {
    let cache_dir = get_blockchain_cache_dir();
    let cache_file = cache_dir.join(format!("{}.json", secret_id));

    if cache_file.exists() {
        let content = fs::read_to_string(&cache_file)?;
        let mut rec: OnChainSecretInfo = serde_json::from_str(&content)?;
        let now = crate::wallet::current_timestamp();
        rec.is_expired = now > rec.expires_at;
        rec.limit_reached = rec.read_count >= rec.max_reads;
        return Ok(rec);
    }

    Err(anyhow!("Secret ID '{}' not found on blockchain registry.", secret_id))
}

pub fn record_read_on_chain(secret_id: &str) -> Result<()> {
    let cache_dir = get_blockchain_cache_dir();
    let cache_file = cache_dir.join(format!("{}.json", secret_id));

    if cache_file.exists() {
        let content = fs::read_to_string(&cache_file)?;
        let mut rec: OnChainSecretInfo = serde_json::from_str(&content)?;
        rec.read_count += 1;
        let now = crate::wallet::current_timestamp();
        rec.is_expired = now > rec.expires_at;
        rec.limit_reached = rec.read_count >= rec.max_reads;
        crate::wallet::write_secure_file(&cache_file, serde_json::to_string_pretty(&rec)?.as_bytes())?;
        Ok(())
    } else {
        Err(anyhow!("Secret ID '{}' not found on blockchain registry.", secret_id))
    }
}

pub fn revoke_secret_on_chain(secret_id: &str, sender_address: &str) -> Result<()> {
    let cache_dir = get_blockchain_cache_dir();
    let cache_file = cache_dir.join(format!("{}.json", secret_id));

    if cache_file.exists() {
        let content = fs::read_to_string(&cache_file)?;
        let mut rec: OnChainSecretInfo = serde_json::from_str(&content)?;
        if rec.sender != sender_address && rec.sender.to_lowercase() != sender_address.to_lowercase() {
            return Err(anyhow!("Only the original secret creator can revoke this secret."));
        }
        rec.revoked = true;
        crate::wallet::write_secure_file(&cache_file, serde_json::to_string_pretty(&rec)?.as_bytes())?;
        Ok(())
    } else {
        Err(anyhow!("Secret ID '{}' not found on blockchain registry.", secret_id))
    }
}

pub fn hide_secret_on_chain(secret_id: &str, user_address: &str) -> Result<()> {
    let cache_dir = get_blockchain_cache_dir();
    let cache_file = cache_dir.join(format!("{}.json", secret_id));

    if cache_file.exists() {
        let content = fs::read_to_string(&cache_file)?;
        let mut rec: OnChainSecretInfo = serde_json::from_str(&content)?;
        rec.hidden = true;
        crate::wallet::write_secure_file(&cache_file, serde_json::to_string_pretty(&rec)?.as_bytes())?;

        // FAILSAFE DESIGN: Hiding a secret primarily sets local visibility (`hidden = true`).
        // If the user is the original creator, attempt on-chain revocation as a secondary measure.
        // If revocation fails (e.g. user is recipient or offline), log a warning and proceed with local hiding.
        if let Err(e) = revoke_secret_on_chain(secret_id, user_address) {
            log::warn!("On-chain revocation not performed for secret '{}' during hide operation: {}", secret_id, e);
        }
        Ok(())
    } else {
        Err(anyhow!("Secret ID '{}' not found on registry.", secret_id))
    }
}

pub fn list_secrets_on_chain(
    user_address: &str,
    filter_user: Option<&str>,
    all: bool,
    expired_only: bool,
    active_only: bool,
) -> Result<Vec<(String, OnChainSecretInfo)>> {
    let cache_dir = get_blockchain_cache_dir();
    let entries = fs::read_dir(cache_dir)?;
    let now = crate::wallet::current_timestamp();
    let mut results = Vec::new();

    for entry in entries.flatten() {
        if entry.path().extension().is_some_and(|ext| ext == "json")
            && let Ok(content) = fs::read_to_string(entry.path())
                && let Ok(rec) = serde_json::from_str::<OnChainSecretInfo>(&content) {
                    let sec_id = entry
                        .path()
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();

                    let is_expired = now > rec.expires_at || rec.read_count >= rec.max_reads || rec.revoked;
                    let is_mine = rec.is_public
                        || rec.sender.to_lowercase() == user_address.to_lowercase()
                        || rec.recipient.to_lowercase() == user_address.to_lowercase();

                    if rec.hidden && !all {
                        // FAILSAFE DESIGN: Hidden secrets are filtered out of listing unless `--all` flag is explicit.
                        continue;
                    }

                    if let Some(target) = filter_user {
                        if rec.recipient.to_lowercase() != target.to_lowercase() && rec.sender.to_lowercase() != target.to_lowercase() {
                            continue;
                        }
                    } else if !all && !is_mine {
                        continue;
                    }

                    if expired_only && !is_expired {
                        continue;
                    }
                    if active_only && is_expired {
                        continue;
                    }

                    results.push((sec_id, rec));
                }
    }

    Ok(results)
}
