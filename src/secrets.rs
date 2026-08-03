use anyhow::{anyhow, Result};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
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

    // --- file-materialization metadata, all optional for backward compat ---
    /// Intended file type of `content` (single-file secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SecretKind>,
    /// Suggested output basename (single-file secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Seal: when true, refuse all file materialization (terminal view only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_export: bool,
    /// Present => this secret is a bundle; materialization iterates members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<BundleMember>>,
    /// Encoding of the single-file `content`: "utf8" (default) or "base64".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    Env,
    Pem,
    Json,
    Cred,
}

fn enc_utf8() -> String {
    "utf8".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BundleMember {
    pub kind: SecretKind,
    /// Basename only, e.g. "creds.json".
    pub filename: String,
    /// The member's plaintext body (whole payload is still AEAD-encrypted at rest).
    pub content: String,
    /// "utf8" (default) or "base64" for binary member bodies.
    #[serde(default = "enc_utf8")]
    pub encoding: String,
    /// Optional explicit env var name to bind this member's staged path to under `run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
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
    let secs = match unit.as_str() {
        "" | "s" | "sec" | "second" | "seconds" => val,
        "m" | "min" | "minute" | "minutes" => {
            val.checked_mul(60).ok_or_else(|| anyhow!("TTL value too large"))?
        }
        "h" | "hr" | "hour" | "hours" => {
            val.checked_mul(3600).ok_or_else(|| anyhow!("TTL value too large"))?
        }
        "d" | "day" | "days" => {
            val.checked_mul(86400).ok_or_else(|| anyhow!("TTL value too large"))?
        }
        "w" | "week" | "weeks" => val
            .checked_mul(86400)
            .ok_or_else(|| anyhow!("TTL value too large"))?
            .checked_mul(7)
            .ok_or_else(|| anyhow!("TTL value too large"))?,
        _ => return Err(anyhow!("Invalid TTL unit (use s, m, h, d, w)")),
    };
    // Enforce a sane upper cap of 100 years.
    if secs > 100 * 365 * 86400 {
        return Err(anyhow!("TTL exceeds maximum (100 years)"));
    }
    Ok(secs)
}

/// Derive an AES-256 wrapper key from a raw ECDH shared secret using HKDF-SHA256 with a
/// fixed domain-separation label, instead of a bare SHA-256 of the shared X coordinate.
fn derive_ecdh_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"bsec-ecdh-aes256gcm-v1", &mut okm)
        .map_err(|_| anyhow!("HKDF key derivation failed"))?;
    Ok(okm)
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

/// Encrypt each bundle member's plaintext body in place with the content key. The IPFS
/// payload JSON is stored cleartext except for these AES-256-GCM ciphertext fields, so
/// member bodies MUST be sealed before upload or they would leak on IPFS.
fn seal_member_bodies(members: &mut [BundleMember], key: &[u8; 32]) -> Result<()> {
    for m in members.iter_mut() {
        m.content = encrypt_text(&m.content, key)?;
    }
    Ok(())
}

/// Decrypt each bundle member's body in place (inverse of `seal_member_bodies`).
fn open_member_bodies(members: &mut [BundleMember], key: &[u8; 32]) -> Result<()> {
    for m in members.iter_mut() {
        m.content = decrypt_text(&m.content, key)?;
    }
    Ok(())
}

/// Metadata describing how a shared secret should be materialized to file(s).
#[derive(Default)]
pub struct ShareMeta {
    pub kind: Option<SecretKind>,
    pub filename: Option<String>,
    pub no_export: bool,
    pub content_encoding: Option<String>,
    /// Plaintext bundle members; their bodies are sealed before upload.
    pub members: Option<Vec<BundleMember>>,
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

    Err(crate::errors::BsecError::InvalidRecipient(
        "Recipient must be a valid SEC1 public key (0x04...), your own wallet address, or 'public'. \
         EVM addresses (0x...) of external users cannot be used for ECDH key exchange without their public key."
            .into(),
    )
    .into())
}

pub fn share_secret(
    content: &str,
    ttl_str: &str,
    max_reads: u32,
    to_address: &str,
    sender_address: &str,
    password: Option<&str>,
    meta: ShareMeta,
) -> Result<SecretRecord> {
    let members_size: usize = meta
        .members
        .as_ref()
        .map(|ms| ms.iter().map(|m| m.content.len()).sum())
        .unwrap_or(0);
    if content.len() + members_size > 10 * 1024 * 1024 {
        return Err(anyhow!("Secret content size exceeds maximum limit of 10MB."));
    }

    let ttl_secs = parse_duration(ttl_str)?;
    let now = crate::wallet::current_timestamp();
    let expires_at = now.checked_add(ttl_secs).ok_or_else(|| anyhow!("expiry timestamp overflow"))?;

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
        derive_ecdh_key(shared_secret.raw_secret_bytes())?
    } else {
        return Err(anyhow!("Cannot resolve recipient public key for encryption."));
    };

    let mut random_content_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(random_content_key.as_mut());

    let encrypted_content = encrypt_text(content, &random_content_key)?;
    let encrypted_content_key = encrypt_text(&BASE64_STANDARD.encode(random_content_key.as_ref()), &wrapper_key)?;

    // Seal bundle member bodies with the same content key before upload (they would
    // otherwise sit in cleartext inside the IPFS payload JSON).
    let sealed_members = match meta.members {
        Some(mut ms) => {
            seal_member_bodies(&mut ms, &random_content_key)?;
            Some(ms)
        }
        None => None,
    };

    let payload = IpfsPayload {
        content: encrypted_content.clone(),
        content_key: encrypted_content_key.clone(),
        ephemeral_pubkey: Some(ephemeral_pub_hex.clone()),
        kind: meta.kind,
        filename: meta.filename,
        no_export: meta.no_export,
        members: sealed_members,
        content_encoding: meta.content_encoding,
    };
    let payload_json = serde_json::to_string(&payload)?;

    let ipfs_cid = upload_to_ipfs(&payload_json)?;

    // Full 256-bit id (0x + 64 hex) so encode_bytes32_hex maps it losslessly onto the
    // contract's bytes32 key. The previous 16-hex-char id was only 64 bits and, being
    // non-hex-prefixed, was packed as ASCII bytes — inviting collisions on the on-chain key.
    let random_nonce: u64 = rand::random();
    let id_seed = format!("{}:{}:{}:{}", sender_address, to_address, now, random_nonce);
    let secret_id = format!("0x{}", bytes_to_hex(&hash_digest(id_seed.as_bytes())));

    let is_public = to_address == "public";

    // On-chain recipient is an EVM address: zero for public, else derived from the
    // recipient's public key (real ECDH confidentiality is enforced separately).
    let recipient_addr: [u8; 20] = if is_public {
        [0u8; 20]
    } else if let Some(ref pk) = recipient_pubkey_opt {
        let ep = pk.to_encoded_point(false);
        let hash = crate::blockchain::keccak256(&ep.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        addr
    } else {
        [0u8; 20]
    };

    let priv_bytes = Zeroizing::new(hex_to_bytes(&sender_info.private_key)?);

    register_secret_on_chain(
        &priv_bytes,
        &secret_id,
        &recipient_addr,
        &ipfs_cid,
        expires_at,
        max_reads,
        is_public,
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
    Ok(view_payload(secret_id, user_address, password)?.content)
}

/// Decrypt a secret and return the WHOLE payload (metadata + plaintext content + plaintext
/// member bodies). Performs authorization, expiry/read-limit checks, and consumes exactly
/// one on-chain read — a bundle counts as one read, not N. Materialize needs this instead
/// of the flattened `view_secret` string because it must see kind/filename/members/no_export.
pub fn view_payload(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<IpfsPayload> {
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
        return Err(crate::errors::BsecError::PermissionDenied("you may not view this secret".into()).into());
    }

    if onchain_info.revoked {
        return Err(anyhow!("Secret with ID '{}' has been revoked.", secret_id));
    }

    let now = crate::wallet::current_timestamp();
    if now > onchain_info.expires_at {
        return Err(crate::errors::BsecError::SecretExpired.into());
    }

    // Public secrets are not read-limited (the contract does not enforce maxReads for them).
    if !onchain_info.is_public && onchain_info.read_count >= onchain_info.max_reads {
        return Err(crate::errors::BsecError::SecretExpired.into());
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
        derive_ecdh_key(shared_secret.raw_secret_bytes())?
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

    let decrypted_content = if payload.content.is_empty() {
        String::new()
    } else {
        decrypt_text(&payload.content, &key_bytes)?
    };

    // Unseal bundle member bodies with the same content key.
    let decrypted_members = match payload.members {
        Some(mut ms) => {
            open_member_bodies(&mut ms, &key_bytes)?;
            Some(ms)
        }
        None => None,
    };

    let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);
    record_read_on_chain(&priv_bytes, secret_id)?;
    crate::blockchain::index_note(secret_id, "recipient");

    Ok(IpfsPayload {
        content: decrypted_content,
        // content_key is consumed above; do not surface the wrapped key to callers.
        content_key: String::new(),
        ephemeral_pubkey: payload.ephemeral_pubkey,
        kind: payload.kind,
        filename: payload.filename,
        no_export: payload.no_export,
        members: decrypted_members,
        content_encoding: payload.content_encoding,
    })
}

/// Decrypt a secret and flatten it into a KEY=VALUE map (env or JSON object). Retained helper
/// for env-style consumers; `run --secret` uses `view_payload` directly so it can also stage
/// file-kind and bundle secrets (calling this would double-count the on-chain read).
#[allow(dead_code)]
pub fn load_secret_as_env(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<std::collections::BTreeMap<String, String>> {
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

pub fn revoke_secret(secret_id: &str, password: Option<&str>) -> Result<()> {
    let wallet_info = crate::wallet::get_wallet_info(password)?;
    let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);
    revoke_secret_on_chain(&priv_bytes, secret_id)
}

pub fn hide_secret(
    secret_id: Option<&str>,
    user_filter: Option<&str>,
    user_address: &str,
    password: Option<&str>,
) -> Result<usize> {
    let wallet_info = crate::wallet::get_wallet_info(password)?;
    let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);

    let onchain_list = list_secrets_on_chain(user_address, user_filter, true, false, false)?;
    let mut hidden_count = 0;

    for (id, rec) in onchain_list {
        let matches_id = secret_id.is_none_or(|target| id == target);
        let matches_filter = user_filter.is_none_or(|target| {
            rec.recipient.to_lowercase() == target.to_lowercase()
                || rec.sender.to_lowercase() == target.to_lowercase()
        });

        if matches_id && matches_filter {
            // Hiding sets local visibility (`hidden = true`) and best-effort revokes on-chain
            // if this wallet is the creator; revocation failure is logged, local hide still applies.
            if hide_secret_on_chain(&priv_bytes, &id).is_ok() {
                hidden_count += 1;
            }
        }
    }

    Ok(hidden_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Backward compat: a payload serialized before this feature has only the three
    // original fields. It MUST still deserialize, with new fields defaulting.
    #[test]
    fn old_payload_json_deserializes_with_defaults() {
        let old_json = r#"{
            "content": "nonce:cipher",
            "content_key": "nonce:wrapped",
            "ephemeral_pubkey": "0x04abcd"
        }"#;
        let p: IpfsPayload = serde_json::from_str(old_json).unwrap();
        assert_eq!(p.content, "nonce:cipher");
        assert_eq!(p.kind, None);
        assert_eq!(p.filename, None);
        assert!(!p.no_export);
        assert!(p.members.is_none());
        assert_eq!(p.content_encoding, None);
    }

    // A single-file secret with no new metadata omits every new field from the wire form,
    // keeping bytes identical to a pre-feature payload.
    #[test]
    fn plain_payload_omits_all_new_fields() {
        let p = IpfsPayload {
            content: "c".to_string(),
            content_key: "k".to_string(),
            ephemeral_pubkey: Some("0x04".to_string()),
            kind: None,
            filename: None,
            no_export: false,
            members: None,
            content_encoding: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("kind"));
        assert!(!json.contains("filename"));
        assert!(!json.contains("no_export"));
        assert!(!json.contains("members"));
        assert!(!json.contains("content_encoding"));
    }

    // A bundle payload survives serialize -> deserialize intact.
    #[test]
    fn bundle_payload_roundtrips() {
        let p = IpfsPayload {
            content: String::new(),
            content_key: "k".to_string(),
            ephemeral_pubkey: None,
            kind: None,
            filename: None,
            no_export: true,
            members: Some(vec![BundleMember {
                kind: SecretKind::Pem,
                filename: "cert.pem".to_string(),
                content: "LS0t".to_string(),
                encoding: "base64".to_string(),
                env: Some("TLS_CERT".to_string()),
            }]),
            content_encoding: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: IpfsPayload = serde_json::from_str(&json).unwrap();
        assert!(back.no_export);
        let m = back.members.unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, SecretKind::Pem);
        assert_eq!(m[0].filename, "cert.pem");
        assert_eq!(m[0].encoding, "base64");
        assert_eq!(m[0].env.as_deref(), Some("TLS_CERT"));
    }

    #[test]
    fn member_bodies_seal_open_roundtrip() {
        let key = [7u8; 32];
        let mut members = vec![
            BundleMember { kind: SecretKind::Pem, filename: "cert.pem".into(), content: "PEM BODY".into(), encoding: "utf8".into(), env: None },
            BundleMember { kind: SecretKind::Env, filename: ".env".into(), content: "K=V".into(), encoding: "utf8".into(), env: None },
        ];
        seal_member_bodies(&mut members, &key).unwrap();
        // sealed bodies are ciphertext, not the original plaintext
        assert_ne!(members[0].content, "PEM BODY");
        assert!(members[0].content.contains(':'));
        open_member_bodies(&mut members, &key).unwrap();
        assert_eq!(members[0].content, "PEM BODY");
        assert_eq!(members[1].content, "K=V");
    }

    #[test]
    fn secret_kind_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&SecretKind::Json).unwrap(), "\"json\"");
        assert_eq!(serde_json::to_string(&SecretKind::Cred).unwrap(), "\"cred\"");
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
    }

    #[test]
    fn parse_duration_empty_defaults_to_one_week() {
        assert_eq!(parse_duration("").unwrap(), 86400 * 7);
    }

    #[test]
    fn parse_duration_multiplication_overflow_is_error() {
        // A number that overflows u64 seconds once multiplied by the week factor.
        assert!(parse_duration("99999999999999999999w").is_err());
        // u64::MAX with a unit that multiplies also overflows.
        assert!(parse_duration(&format!("{}w", u64::MAX)).is_err());
    }

    #[test]
    fn parse_duration_beyond_100_year_cap_is_error() {
        // 101 years in seconds is within u64 but exceeds the 100-year cap.
        let one_hundred_one_years = 101u64 * 365 * 86400;
        assert!(parse_duration(&format!("{}s", one_hundred_one_years)).is_err());
        // Also via a unit-based value clearly beyond the cap.
        assert!(parse_duration("6000w").is_err());
    }
}
