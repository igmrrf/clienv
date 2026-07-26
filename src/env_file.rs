use anyhow::{anyhow, Result};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::wallet::{derive_key_legacy, set_private_file_permissions};

pub fn parse_env_content(content: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim().to_string();
            let mut val_str = val.trim();
            if let Some(pos) = val_str.find(" #") {
                val_str = val_str[..pos].trim();
            }
            let mut val = val_str.to_string();
            if (val.starts_with('\'') && val.ends_with('\''))
                || (val.starts_with('"') && val.ends_with('"'))
            {
                if val.len() >= 2 {
                    val = val[1..val.len() - 1].to_string();
                }
            }
            val = val.replace("\\\"", "\"").replace("\\'", "'");
            map.insert(key, val);
        }
    }
    map
}

pub fn parse_json_content(content: &str) -> Result<BTreeMap<String, String>> {
    let val: Value = serde_json::from_str(content)?;
    let mut map = BTreeMap::new();
    if let Value::Object(obj) = val {
        for (k, v) in obj {
            match v {
                Value::String(s) => {
                    map.insert(k, s);
                }
                Value::Number(n) => {
                    map.insert(k, n.to_string());
                }
                Value::Bool(b) => {
                    map.insert(k, b.to_string());
                }
                _ => {
                    map.insert(k, v.to_string());
                }
            }
        }
    }
    Ok(map)
}

pub fn convert_env_file(
    input_file: &Path,
    output_file: &Path,
    format_opt: &str,
    prefix: Option<&str>,
    suffix: Option<&str>,
    embed: Option<&str>,
) -> Result<()> {
    let content = fs::read_to_string(input_file)?;
    let ext = input_file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mut map = match ext.as_str() {
        "env" | "local" | "dev" | "prod" => parse_env_content(&content),
        "json" => parse_json_content(&content)?,
        _ => parse_env_content(&content),
    };

    if let Some(pref) = prefix {
        let mut new_map = BTreeMap::new();
        for (k, v) in map {
            new_map.insert(format!("{}{}", pref, k), v);
        }
        map = new_map;
    }

    if let Some(suf) = suffix {
        let mut new_map = BTreeMap::new();
        for (k, v) in map {
            new_map.insert(format!("{}{}", k, suf), v);
        }
        map = new_map;
    }

    let s = suffix.unwrap_or("");

    let output_str = if let Some(embed_prefix) = embed {
        let mut lines = Vec::new();
        lines.push("{".to_string());
        for (k, _) in &map {
            lines.push(format!("  {}: '{}{}{}',", k, embed_prefix, k, s));
        }
        lines.push("}".to_string());
        lines.join("\n")
    } else {
        match format_opt.to_lowercase().as_str() {
            "json" => {
                let mut json_obj = Map::new();
                for (k, v) in map {
                    json_obj.insert(k, Value::String(v));
                }
                serde_json::to_string_pretty(&json_obj)?
            }
            "yaml" | "yml" => serde_yaml::to_string(&map)?,
            _ => {
                let mut lines = Vec::new();
                for (k, v) in map {
                    lines.push(format!("{}='{}'", k, v));
                }
                lines.join("\n")
            }
        }
    };

    fs::write(output_file, output_str)?;
    Ok(())
}

pub fn validate_env_file(schema_path: &Path, env_path: &Path) -> Result<()> {
    if !schema_path.exists() {
        return Err(anyhow!("Schema file '{}' does not exist.", schema_path.display()));
    }

    let schema_content = fs::read_to_string(schema_path)?;
    let schema_map = parse_env_content(&schema_content);

    if !env_path.exists() {
        println!("Environment file '{}' does not exist. Creating from schema...", env_path.display());
        let mut lines = Vec::new();
        for (k, _) in &schema_map {
            lines.push(format!("{}=", k));
        }
        fs::write(env_path, lines.join("\n"))?;
        println!("Environment file created successfully.");
        return Ok(());
    }

    let env_content = fs::read_to_string(env_path)?;
    let env_map = parse_env_content(&env_content);

    let mut missing_keys = Vec::new();
    for (k, _) in &schema_map {
        if !env_map.contains_key(k) {
            missing_keys.push(k);
        }
    }

    if !missing_keys.is_empty() {
        println!("Warning: The following keys are missing in '{}':", env_path.display());
        for key in &missing_keys {
            println!("  - {}", key);
        }
        let mut new_lines = vec![env_content.trim_end().to_string()];
        for key in missing_keys {
            new_lines.push(format!("{}=", key));
        }
        fs::write(env_path, new_lines.join("\n"))?;
        println!("Updated '{}' with missing keys.", env_path.display());
    } else {
        println!("Environment file '{}' is valid and matches schema.", env_path.display());
    }

    Ok(())
}

pub fn generate_template(env_path: &Path, output_path: &Path) -> Result<()> {
    let content = fs::read_to_string(env_path)?;
    let map = parse_env_content(&content);

    let mut lines = Vec::new();
    for (k, _) in map {
        lines.push(format!("{}=#Your {} here", k, k));
    }

    fs::write(output_path, lines.join("\n"))?;
    Ok(())
}

pub fn log_env_var(var_name: &str, file_path: &Path) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let map = if ext == "json" {
        parse_json_content(&content)?
    } else {
        parse_env_content(&content)
    };

    if let Some(val) = map.get(var_name) {
        println!("{}: {}", var_name, val);
    } else {
        println!("Environment variable '{}' not found in '{}'", var_name, file_path.display());
    }

    Ok(())
}

fn derive_pass_key(pass: &str) -> [u8; 32] {
    derive_key_legacy(pass)
}

pub fn get_encryption_password(env_file_name: &str) -> Result<String> {
    let file_stem = Path::new(env_file_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(env_file_name);

    let clean_stem = file_stem.replace('.', "_").to_uppercase();
    let env_specific_var = format!("DOTENV_{}_PASS", clean_stem);
    if let Ok(val) = std::env::var(&env_specific_var) {
        return Ok(val);
    }

    if let Ok(val) = std::env::var("DOTENV_PASS") {
        return Ok(val);
    }

    let pass_file = format!("{}.pass", file_stem);
    if Path::new(&pass_file).exists() {
        if let Ok(val) = fs::read_to_string(&pass_file) {
            return Ok(val.trim().to_string());
        }
    }

    if Path::new(".env.pass").exists() {
        if let Ok(val) = fs::read_to_string(".env.pass") {
            return Ok(val.trim().to_string());
        }
    }

    Err(anyhow!(
        "No encryption password found. Set $DOTENV_PASS environment variable."
    ))
}

pub fn encrypt_env_file(input_file: &Path, output_file: Option<&Path>) -> Result<PathBuf> {
    let content = fs::read_to_string(input_file)?;
    let file_name = input_file.to_string_lossy().to_string();
    let password = get_encryption_password(&file_name)?;
    let key = derive_pass_key(&password);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("key init failed"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, content.as_bytes())
        .map_err(|_| anyhow!("encryption failed"))?;

    let payload = format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    );

    let target_path = match output_file {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(format!("{}.enc", input_file.display())),
    };

    fs::write(&target_path, payload)?;
    set_private_file_permissions(&target_path);
    Ok(target_path)
}

pub fn decrypt_env_file(input_file: &Path, output_file: Option<&Path>) -> Result<PathBuf> {
    let payload = fs::read_to_string(input_file)?;
    let file_name = input_file.to_string_lossy().to_string();
    let clean_name = file_name.trim_end_matches(".enc").trim_end_matches(".encrypted");
    let password = get_encryption_password(clean_name)?;
    let key = derive_pass_key(&password);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("key init failed"))?;
    let parts: Vec<&str> = payload.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid encrypted payload format"));
    }

    let nonce_bytes = BASE64_STANDARD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid nonce"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher_bytes = BASE64_STANDARD
        .decode(parts[1])
        .map_err(|_| anyhow!("Invalid cipher text"))?;

    let plain_bytes = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Check your password."))?;
    let plain_str = String::from_utf8(plain_bytes)?;

    let target_path = match output_file {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(clean_name),
    };

    fs::write(&target_path, plain_str)?;
    Ok(target_path)
}

pub fn load_and_parse_env(env_path: &Path) -> Result<BTreeMap<String, String>> {
    let file_str = env_path.to_string_lossy();
    if file_str.ends_with(".enc") || file_str.ends_with(".encrypted") {
        let payload = fs::read_to_string(env_path)?;
        let clean_name = file_str.trim_end_matches(".enc").trim_end_matches(".encrypted");
        let password = get_encryption_password(clean_name)?;
        let key = derive_pass_key(&password);

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("key init failed"))?;
        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid encrypted payload format"));
        }
        let nonce_bytes = BASE64_STANDARD.decode(parts[0])?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher_bytes = BASE64_STANDARD.decode(parts[1])?;
        let plain_bytes = cipher
            .decrypt(nonce, cipher_bytes.as_ref())
            .map_err(|_| anyhow!("Decryption failed. Check password."))?;
        let plain_str = String::from_utf8(plain_bytes)?;
        Ok(parse_env_content(&plain_str))
    } else {
        let content = fs::read_to_string(env_path)?;
        let ext = env_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "json" {
            parse_json_content(&content)
        } else {
            Ok(parse_env_content(&content))
        }
    }
}

pub fn run_with_envs(
    env_file: Option<&Path>,
    secret_id: Option<&str>,
    command_and_args: &[String],
) -> Result<i32> {
    if command_and_args.is_empty() {
        return Err(anyhow!("No command provided. Usage: bsec run -- <command>"));
    }

    let mut env_map = BTreeMap::new();

    let proj_config = crate::project_config::load_project_config();

    let target_secret_id = secret_id.or_else(|| {
        proj_config.as_ref().and_then(|p| p.secret_id.as_deref())
    });

    let target_env_file = env_file.or_else(|| {
        proj_config
            .as_ref()
            .and_then(|p| p.env_file.as_ref().map(Path::new))
    });

    if let Some(sec_id) = target_secret_id {
        let user_addr = crate::wallet::get_wallet_info(None)?.address.clone();
        let sec_vars = crate::secrets::load_secret_as_env(sec_id, &user_addr)?;
        env_map.extend(sec_vars);
    }

    if let Some(file_path) = target_env_file {
        if file_path.exists() {
            let file_vars = load_and_parse_env(file_path)?;
            env_map.extend(file_vars);
        }
    } else if target_secret_id.is_none() {
        let default_local = Path::new(".env.local");
        if default_local.exists() {
            let file_vars = load_and_parse_env(default_local)?;
            env_map.extend(file_vars);
        } else {
            let default_env = Path::new(".env");
            if default_env.exists() {
                let file_vars = load_and_parse_env(default_env)?;
                env_map.extend(file_vars);
            }
        }
    }

    let mut child = Command::new(&command_and_args[0]);
    child.args(&command_and_args[1..]);

    for (k, v) in env_map {
        child.env(k, v);
    }

    child.stdin(Stdio::inherit());
    child.stdout(Stdio::inherit());
    child.stderr(Stdio::inherit());

    let status = child.status()?;
    Ok(status.code().unwrap_or(0))
}
