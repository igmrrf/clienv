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

/// Encode a secret ID string into a bytes32 contract key. Only two shapes are accepted,
/// both mapped losslessly and left-aligned:
///
/// - a "0x"-prefixed hex string that decodes to AT MOST 32 bytes, or
/// - a non-hex ID whose raw UTF-8 is AT MOST 32 bytes.
///
/// Anything longer is rejected rather than silently truncated — silent truncation let
/// distinct IDs collide on the same on-chain bytes32 key.
pub fn encode_bytes32_hex(id_str: &str) -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    if id_str.starts_with("0x") {
        let b = crate::wallet::hex_to_bytes(id_str)?;
        if b.len() > 32 {
            return Err(anyhow!("secret ID {:?} decodes to {} bytes; max 32", id_str, b.len()));
        }
        bytes[..b.len()].copy_from_slice(&b);
        return Ok(bytes);
    }
    let raw = id_str.as_bytes();
    if raw.len() > 32 {
        return Err(anyhow!("secret ID {:?} is {} bytes; max 32", id_str, raw.len()));
    }
    bytes[..raw.len()].copy_from_slice(raw);
    Ok(bytes)
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
    let id32 = encode_bytes32_hex(secret_id)?;
    let data = eth::encode_share_secret(&id32, recipient_addr, ipfs_cid, expires_at, max_reads, is_public);
    let tx_hash = eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    index_note(secret_id, "sender");
    Ok(tx_hash)
}

pub fn get_secret_info_on_chain(secret_id: &str) -> Result<OnChainSecretInfo> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id)?;
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
    let id32 = encode_bytes32_hex(secret_id)?;
    let data = eth::encode_bytes32_call("recordRead(bytes32)", &id32);
    eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    Ok(())
}

pub fn revoke_secret_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_0x_64hex_decodes_to_32_bytes() {
        let id = format!("0x{}", "ab".repeat(32)); // 0x + 64 hex chars = 32 bytes
        let out = encode_bytes32_hex(&id).expect("valid 32-byte hex id must encode");
        assert_eq!(out, [0xabu8; 32]);
    }

    #[test]
    fn oversized_0x_hex_is_rejected() {
        let id = format!("0x{}", "cd".repeat(33)); // decodes to 33 bytes > 32
        assert!(encode_bytes32_hex(&id).is_err());
    }

    #[test]
    fn oversized_raw_id_is_rejected() {
        let id = "z".repeat(33); // non-hex raw id, 33 bytes > 32
        assert!(encode_bytes32_hex(&id).is_err());
    }

    #[test]
    fn short_raw_id_is_left_aligned() {
        let out = encode_bytes32_hex("hello").expect("short raw id must encode");
        let mut expected = [0u8; 32];
        expected[..5].copy_from_slice(b"hello");
        assert_eq!(out, expected);
    }

    #[test]
    fn checksum_address_eip55_known_vectors() {
        // Parse a 40-hex string into a fixed 20-byte address.
        fn addr(hex: &str) -> [u8; 20] {
            let bytes = crate::wallet::hex_to_bytes(hex).expect("valid 40-hex address");
            let mut out = [0u8; 20];
            out.copy_from_slice(&bytes);
            out
        }

        // Official EIP-55 checksum vectors.
        assert_eq!(
            bytes_to_checksum_address(&addr("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert_eq!(
            bytes_to_checksum_address(&addr("fb6916095ca1df60bb79ce92ce3ea74c37c5d359")),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(
            bytes_to_checksum_address(&addr("dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb")),
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        );
    }
}
