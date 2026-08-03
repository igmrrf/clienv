//! On-chain registry access for BsecSecretRegistry.
//!
//! All state-changing operations are real signed transactions; all reads are real
//! `eth_call`s against the configured RPC node (remote or local anvil). A local index
//! (`~/.bsec/secret_index.json`) only enumerates the secret IDs this wallet has created or
//! viewed and tracks a local-only `hidden` flag — the authoritative state (reads, revocation,
//! expiry, recipient) always comes from the chain.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::eth;
use crate::network_config::{load_network_config, NetworkConfig};

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

/// Encode a secret ID string into a bytes32 contract key. Hex "0x..." IDs are decoded;
/// other IDs use their raw UTF-8 bytes. Both are used consistently for register and read.
pub fn encode_bytes32_hex(id_str: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if id_str.starts_with("0x")
        && let Ok(b) = crate::wallet::hex_to_bytes(id_str)
    {
        let len = b.len().min(32);
        bytes[..len].copy_from_slice(&b[..len]);
        return bytes;
    }
    let len = id_str.len().min(32);
    bytes[..len].copy_from_slice(&id_str.as_bytes()[..len]);
    bytes
}

fn registry_address(conf: &NetworkConfig) -> Result<[u8; 20]> {
    eth::parse_address(&conf.registry_address).map_err(|e| {
        anyhow!(
            "Invalid registry_address '{}' in network config: {}",
            conf.registry_address,
            e
        )
    })
}

// ---------------------------------------------------------------------------
// Local index (enumeration + hidden flag only)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct IndexEntry {
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    role: String,
}

type Index = BTreeMap<String, IndexEntry>;

fn index_path() -> PathBuf {
    crate::wallet::get_app_dir().join("secret_index.json")
}

fn load_index() -> Index {
    match fs::read_to_string(index_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Index::new(),
    }
}

fn save_index(index: &Index) -> Result<()> {
    let content = serde_json::to_string_pretty(index)?;
    crate::wallet::write_secure_file(&index_path(), content.as_bytes())
}

/// Record that this wallet knows about a secret (created or received), for `list`.
pub fn index_note(secret_id: &str, role: &str) {
    let mut index = load_index();
    let entry = index.entry(secret_id.to_string()).or_default();
    if entry.role.is_empty() {
        entry.role = role.to_string();
    }
    let _ = save_index(&index);
}

fn index_set_hidden(secret_id: &str, hidden: bool) {
    let mut index = load_index();
    index.entry(secret_id.to_string()).or_default().hidden = hidden;
    let _ = save_index(&index);
}

fn index_is_hidden(secret_id: &str) -> bool {
    load_index().get(secret_id).map(|e| e.hidden).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Contract operations
// ---------------------------------------------------------------------------

/// Register a secret on-chain via a signed shareSecret transaction. Returns the tx hash.
pub fn register_secret_on_chain(
    priv_bytes: &[u8],
    secret_id: &str,
    recipient_addr: &[u8; 20],
    ipfs_cid: &str,
    expires_at: u64,
    max_reads: u32,
    is_public: bool,
) -> Result<String> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id);
    let data = eth::encode_share_secret(&id32, recipient_addr, ipfs_cid, expires_at, max_reads, is_public);
    let tx_hash = eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    index_note(secret_id, "sender");
    Ok(tx_hash)
}

pub fn get_secret_info_on_chain(secret_id: &str) -> Result<OnChainSecretInfo> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id);
    let data = eth::encode_bytes32_call("getSecretInfo(bytes32)", &id32);

    let ret = eth::eth_call(&conf, &to, &data).map_err(|e| {
        anyhow!("Secret ID '{}' not found on-chain (or RPC error): {}", secret_id, e)
    })?;
    if ret.is_empty() {
        return Err(anyhow!("Secret ID '{}' not found on blockchain registry.", secret_id));
    }
    let d = eth::decode_secret_info(&ret)?;

    let recipient = if d.is_public {
        "public".to_string()
    } else {
        bytes_to_checksum_address(&d.recipient)
    };

    Ok(OnChainSecretInfo {
        sender: bytes_to_checksum_address(&d.sender),
        recipient,
        ipfs_cid: d.ipfs_cid,
        created_at: d.created_at,
        expires_at: d.expires_at,
        max_reads: d.max_reads,
        read_count: d.read_count,
        revoked: d.revoked,
        is_public: d.is_public,
        is_expired: d.is_expired,
        limit_reached: d.limit_reached,
        hidden: index_is_hidden(secret_id),
    })
}

pub fn record_read_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id);
    let data = eth::encode_bytes32_call("recordRead(bytes32)", &id32);
    eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    Ok(())
}

pub fn revoke_secret_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id);
    let data = eth::encode_bytes32_call("revokeSecret(bytes32)", &id32);
    eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    Ok(())
}

/// Hide a secret locally (contract has no hidden state) and best-effort revoke on-chain.
pub fn hide_secret_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    index_set_hidden(secret_id, true);
    if let Err(e) = revoke_secret_on_chain(priv_bytes, secret_id) {
        log::warn!(
            "On-chain revocation not performed for secret '{}' during hide (kept local hide): {}",
            secret_id,
            e
        );
    }
    Ok(())
}

pub fn list_secrets_on_chain(
    user_address: &str,
    filter_user: Option<&str>,
    all: bool,
    expired_only: bool,
    active_only: bool,
) -> Result<Vec<(String, OnChainSecretInfo)>> {
    let index = load_index();
    let mut results = Vec::new();

    for (sec_id, entry) in index.iter() {
        let rec = match get_secret_info_on_chain(sec_id) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Skipping secret '{}' in listing (chain read failed): {}", sec_id, e);
                continue;
            }
        };

        let is_expired = rec.is_expired || rec.limit_reached || rec.revoked;
        let is_mine = rec.is_public
            || rec.sender.to_lowercase() == user_address.to_lowercase()
            || rec.recipient.to_lowercase() == user_address.to_lowercase();

        if entry.hidden && !all {
            continue;
        }

        if let Some(target) = filter_user {
            if rec.recipient.to_lowercase() != target.to_lowercase()
                && rec.sender.to_lowercase() != target.to_lowercase()
            {
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

        results.push((sec_id.clone(), rec));
    }

    Ok(results)
}
