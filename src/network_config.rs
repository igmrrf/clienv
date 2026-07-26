use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpfsConfig {
    pub gateway: String,
    pub pinning_service: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub network: String,
    pub chain_id: u32,
    pub rpc_url: String,
    pub ipfs: IpfsConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: "polygon".to_string(),
            chain_id: 137,
            rpc_url: "https://polygon-rpc.com".to_string(),
            ipfs: IpfsConfig {
                gateway: "https://ipfs.io/ipfs/".to_string(),
                pinning_service: None,
            },
        }
    }
}

pub fn get_config_path() -> PathBuf {
    crate::wallet::get_app_dir().join("network-config.json")
}

pub fn load_network_config() -> NetworkConfig {
    let path = get_config_path();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(config) = serde_json::from_str(&content) {
                return config;
            }
        }
    }
    NetworkConfig::default()
}

pub fn save_network_config(config: &NetworkConfig) -> Result<()> {
    let path = get_config_path();
    let content = serde_json::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

pub fn update_network_config(
    network: Option<String>,
    rpc: Option<String>,
    ipfs_gateway: Option<String>,
    ipfs_pinning: Option<String>,
) -> Result<NetworkConfig> {
    let mut config = load_network_config();

    if let Some(net) = network {
        match net.to_lowercase().as_str() {
            "polygon" => {
                config.network = "polygon".to_string();
                config.chain_id = 137;
                if rpc.is_none() {
                    config.rpc_url = "https://polygon-rpc.com".to_string();
                }
            }
            "base" => {
                config.network = "base".to_string();
                config.chain_id = 8453;
                if rpc.is_none() {
                    config.rpc_url = "https://mainnet.base.org".to_string();
                }
            }
            "local" | "anvil" | "hardhat" => {
                config.network = "local".to_string();
                config.chain_id = 31337;
                if rpc.is_none() {
                    config.rpc_url = "http://localhost:8545".to_string();
                }
            }
            "amoy" => {
                config.network = "amoy".to_string();
                config.chain_id = 80002;
                if rpc.is_none() {
                    config.rpc_url = "https://rpc-amoy.polygon.technology".to_string();
                }
            }
            "sepolia" => {
                config.network = "sepolia".to_string();
                config.chain_id = 11155111;
                if rpc.is_none() {
                    config.rpc_url = "https://rpc.sepolia.org".to_string();
                }
            }
            "base-sepolia" => {
                config.network = "base-sepolia".to_string();
                config.chain_id = 84532;
                if rpc.is_none() {
                    config.rpc_url = "https://sepolia.base.org".to_string();
                }
            }
            "ethereum" => {
                config.network = "ethereum".to_string();
                config.chain_id = 1;
                if rpc.is_none() {
                    config.rpc_url = "https://mainnet.infura.io/v3/your-infura-key".to_string();
                }
            }
            custom => {
                config.network = custom.to_string();
            }
        }
    }

    if let Some(r) = rpc {
        config.rpc_url = r;
    }

    if let Some(g) = ipfs_gateway {
        config.ipfs.gateway = g;
    }

    if let Some(p) = ipfs_pinning {
        config.ipfs.pinning_service = Some(p);
    }

    save_network_config(&config)?;
    Ok(config)
}
