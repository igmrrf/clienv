use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProjectConfig {
    pub secret_id: Option<String>,
    pub env_file: Option<String>,
    pub schema_file: Option<String>,
    pub network: Option<String>,
}

pub fn get_project_config_path() -> PathBuf {
    PathBuf::from(".bsec.json")
}

pub fn load_project_config() -> Option<ProjectConfig> {
    let path = get_project_config_path();
    if let Ok(content) = fs::read_to_string(&path)
        && let Ok(config) = serde_json::from_str::<ProjectConfig>(&content) {
            return Some(config);
        }
    None
}

#[allow(dead_code)]
pub fn save_project_config(config: &ProjectConfig) -> anyhow::Result<()> {
    let path = get_project_config_path();
    let content = serde_json::to_string_pretty(config)?;
    crate::wallet::write_secure_file(&path, content.as_bytes())?;
    Ok(())
}
