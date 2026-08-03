//! Real IPFS storage.
//!
//! Upload: Pinata `pinFileToIPFS` when a JWT is configured, otherwise a Kubo RPC daemon
//! (`/api/v0/add`). Fetch: local cache, then Kubo `cat`, then the configured and public
//! gateways. No mock CIDs, no fabricated success — an unreachable backend returns an error.
//!
//! Integrity: payloads are AES-256-GCM encrypted, so a tampered or substituted blob fails
//! AEAD authentication (or JSON parsing) downstream rather than silently compromising the
//! secret. Reproducing IPFS dag-pb chunking to recompute the CID is therefore unnecessary.

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::network_config::NetworkConfig;

const IPFS_TIMEOUT_SECS: u64 = 15;

pub fn get_ipfs_cache_dir() -> PathBuf {
    let dir = crate::wallet::get_app_dir().join("ipfs_cache");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(IPFS_TIMEOUT_SECS))
        .build()
        .map_err(|e| anyhow!("failed to build IPFS HTTP client: {}", e))
}

fn resolve_pinning_jwt(conf: &NetworkConfig) -> Option<String> {
    conf.ipfs
        .pinning_jwt
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("BSEC_PINATA_JWT").ok().filter(|s| !s.trim().is_empty()))
}

fn cache_payload(cid: &str, payload_json: &str) {
    let cache_file = get_ipfs_cache_dir().join(format!("{}.json", cid));
    let _ = crate::wallet::write_secure_file(&cache_file, payload_json.as_bytes());
}

fn pin_via_pinata(client: &Client, jwt: &str, payload_json: &str) -> Result<String> {
    let form = reqwest::blocking::multipart::Form::new()
        .text("file", payload_json.to_string());
    let res = client
        .post("https://api.pinata.cloud/pinning/pinFileToIPFS")
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .map_err(|e| anyhow!("Pinata request failed: {}", e))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().unwrap_or_default();
        return Err(anyhow!("Pinata pinning failed ({}): {}", status, body));
    }
    let json: serde_json::Value = res.json().map_err(|e| anyhow!("Pinata response decode error: {}", e))?;
    let cid = json
        .get("IpfsHash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("Pinata response missing IpfsHash"))?;
    Ok(cid.to_string())
}

fn add_via_kubo(client: &Client, api_url: &str, payload_json: &str) -> Result<String> {
    let url = format!("{}/api/v0/add", api_url.trim_end_matches('/'));
    let form = reqwest::blocking::multipart::Form::new()
        .text("file", payload_json.to_string());
    let res = client
        .post(&url)
        .multipart(form)
        .send()
        .map_err(|e| anyhow!("IPFS daemon request to {} failed: {}", url, e))?;
    if !res.status().is_success() {
        return Err(anyhow!("IPFS daemon add failed ({})", res.status()));
    }
    let json: serde_json::Value = res.json().map_err(|e| anyhow!("IPFS add response decode error: {}", e))?;
    let cid = json
        .get("Hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("IPFS add response missing Hash"))?;
    Ok(cid.to_string())
}

/// Upload a payload to IPFS. Returns a real CID. Errors if no backend is reachable.
pub fn upload_to_ipfs(payload_json: &str) -> Result<String> {
    let conf = crate::network_config::load_network_config();
    let client = client()?;

    // 1. Hosted pinning (Pinata) if a JWT is configured — persists across machines.
    if let Some(jwt) = resolve_pinning_jwt(&conf) {
        match pin_via_pinata(&client, &jwt, payload_json) {
            Ok(cid) => {
                cache_payload(&cid, payload_json);
                return Ok(cid);
            }
            Err(e) => log::warn!("Pinata pinning failed, trying local IPFS daemon: {}", e),
        }
    }

    // 2. Local / self-hosted Kubo daemon.
    match add_via_kubo(&client, &conf.ipfs.api_url, payload_json) {
        Ok(cid) => {
            cache_payload(&cid, payload_json);
            Ok(cid)
        }
        Err(e) => Err(anyhow!(
            "No IPFS backend available. Configure a Pinata JWT (ipfs.pinning_jwt or \
             BSEC_PINATA_JWT) or run a local IPFS daemon reachable at {}. Last error: {}",
            conf.ipfs.api_url,
            e
        )),
    }
}

fn cat_via_kubo(client: &Client, api_url: &str, cid: &str) -> Option<String> {
    let url = format!("{}/api/v0/cat?arg={}", api_url.trim_end_matches('/'), cid);
    match client.post(&url).send() {
        Ok(res) if res.status().is_success() => res.text().ok(),
        _ => None,
    }
}

/// Fetch a payload by CID: local cache, then Kubo daemon, then gateways.
pub fn fetch_from_ipfs(cid: &str) -> Result<String> {
    let conf = crate::network_config::load_network_config();
    let cache_dir = get_ipfs_cache_dir();

    // 1. Local cache.
    let cache_file = cache_dir.join(format!("{}.json", cid));
    if let Ok(cached) = fs::read_to_string(&cache_file) {
        return Ok(cached);
    }

    let client = client()?;

    // 2. Kubo daemon cat.
    if let Some(text) = cat_via_kubo(&client, &conf.ipfs.api_url, cid) {
        let _ = crate::wallet::write_secure_file(&cache_file, text.as_bytes());
        return Ok(text);
    }

    // 3. Configured + public gateways.
    let configured = format!(
        "{}{}",
        conf.ipfs.gateway.trim_end_matches('/'),
        "/",
    );
    let gateways = [
        configured,
        "https://ipfs.io/ipfs/".to_string(),
        "https://dweb.link/ipfs/".to_string(),
    ];

    for gw in gateways {
        let url = format!("{}{}", gw, cid);
        if let Ok(res) = client.get(&url).send()
            && res.status().is_success()
            && let Ok(text) = res.text()
        {
            let _ = crate::wallet::write_secure_file(&cache_file, text.as_bytes());
            return Ok(text);
        }
    }

    Err(anyhow!(
        "Failed to fetch payload for IPFS CID '{}' from daemon or gateways.",
        cid
    ))
}
