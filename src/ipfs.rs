use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub fn get_ipfs_cache_dir() -> PathBuf {
    let dir = crate::wallet::get_app_dir().join("ipfs_cache");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

pub fn compute_mock_cid(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let hash = hasher.finalize();
    let hex_str = crate::wallet::bytes_to_hex(&hash[0..16]);
    format!("QmBsecMock{}", hex_str)
}

pub fn upload_to_ipfs(payload_json: &str) -> Result<String> {
    let _conf = crate::network_config::load_network_config();
    let cache_dir = get_ipfs_cache_dir();

    // 1. Check local node / daemon if available
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // Try local IPFS RPC endpoint if running
    let form = reqwest::blocking::multipart::Form::new().text("file", payload_json.to_string());
    if let Ok(res) = client
        .post("http://127.0.0.1:5001/api/v0/add")
        .multipart(form)
        .send()
        && res.status().is_success()
            && let Ok(json) = res.json::<serde_json::Value>()
                && let Some(cid) = json.get("Hash").and_then(|h| h.as_str()) {
                    let cache_file = cache_dir.join(format!("{}.json", cid));
                    let _ = fs::write(&cache_file, payload_json);
                    return Ok(cid.to_string());
                }

    // 2. Fallback to computing deterministic multihash CID and storing in local cache
    let cid = compute_mock_cid(payload_json.as_bytes());
    let cache_file = cache_dir.join(format!("{}.json", cid));
    crate::wallet::write_secure_file(&cache_file, payload_json.as_bytes())?;

    Ok(cid)
}

pub fn fetch_from_ipfs(cid: &str) -> Result<String> {
    let conf = crate::network_config::load_network_config();
    let cache_dir = get_ipfs_cache_dir();

    // 1. Check local cache first
    let cache_file = cache_dir.join(format!("{}.json", cid));
    if let Ok(cached) = fs::read_to_string(&cache_file) {
        return Ok(cached);
    }

    // 2. Fetch from configured IPFS gateways
    let gateways = vec![
        format!("{}{}", conf.ipfs.gateway.trim_end_matches('/'), if conf.ipfs.gateway.ends_with('/') { "" } else { "/" }),
        "https://ipfs.io/ipfs/".to_string(),
        "https://dweb.link/ipfs/".to_string(),
        "http://127.0.0.1:8080/ipfs/".to_string(),
    ];

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    for gw in gateways {
        let url = format!("{}{}", gw, cid);
        if let Ok(res) = client.get(&url).send()
            && res.status().is_success()
                && let Ok(text) = res.text() {
                    let _ = crate::wallet::write_secure_file(&cache_file, text.as_bytes());
                    return Ok(text);
                }
    }

    Err(anyhow!("Failed to fetch payload for IPFS CID '{}' from all gateways", cid))
}
