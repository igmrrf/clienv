use anyhow::{anyhow, Result};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::prelude::*;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use crate::wallet::{derive_key_legacy, write_secure_file};

pub fn parse_env_content(content: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let clean_line = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((key, val)) = clean_line.split_once('=') {
            let key = key.trim().to_string();
            let mut val_str = val.trim();
            let is_single_quoted = val_str.starts_with('\'') && val_str.ends_with('\'') && val_str.len() >= 2;
            let is_double_quoted = val_str.starts_with('"') && val_str.ends_with('"') && val_str.len() >= 2;

            let parsed_val = if is_single_quoted {
                let inner = &val_str[1..val_str.len() - 1];
                inner.replace("\\'", "'")
            } else if is_double_quoted {
                let inner = &val_str[1..val_str.len() - 1];
                inner
                    .replace("\\n", "\n")
                    .replace("\\t", "\t")
                    .replace("\\r", "\r")
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
            } else {
                if let Some(pos) = val_str.find(" #") {
                    val_str = val_str[..pos].trim();
                } else if let Some(pos) = val_str.find('#') {
                    if pos == 0 {
                        val_str = "";
                    } else if val_str.as_bytes()[pos - 1].is_ascii_whitespace() {
                        val_str = val_str[..pos].trim();
                    }
                }
                val_str.to_string()
            };

            map.insert(key, parsed_val);
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

    let output_str = if let Some(embed_prefix) = embed {
        let mut lines = Vec::new();
        lines.push("{".to_string());
        for k in map.keys() {
            lines.push(format!("  {}: '{}{}',", k, embed_prefix, k));
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
            "yaml" | "yml" => yaml_serde::to_string(&map)?,
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
        for k in schema_map.keys() {
            lines.push(format!("{}=", k));
        }
        fs::write(env_path, lines.join("\n"))?;
        println!("Environment file created successfully.");
        return Ok(());
    }

    let env_content = fs::read_to_string(env_path)?;
    let env_map = parse_env_content(&env_content);

    let mut missing_keys = Vec::new();
    for k in schema_map.keys() {
        if !env_map.contains_key(k) {
            missing_keys.push(k);
        }
    }

    if !missing_keys.is_empty() {
        println!("Warning: The following keys are missing in '{}':", env_path.display());
        for key in &missing_keys {
            println!("  - {}", key);
        }
        let trimmed_content = env_content.trim_end();
        let mut new_lines = if trimmed_content.is_empty() {
            Vec::new()
        } else {
            vec![trimmed_content.to_string()]
        };
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

pub fn get_encryption_password(env_file_name: &str, provided_pwd: Option<&str>) -> Result<String> {
    if let Some(p) = provided_pwd
        && !p.is_empty() {
            return Ok(p.to_string());
        }

    let file_stem = Path::new(env_file_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(env_file_name);

    let clean_stem = file_stem
        .trim_start_matches('.')
        .replace('.', "_")
        .to_uppercase();

    let env_specific_var = format!("DOTENV_{}_PASS", clean_stem);
    if let Ok(val) = std::env::var(&env_specific_var) {
        return Ok(val);
    }

    let alt_var = format!("DOTENV_{}_PASS", clean_stem.trim_start_matches("ENV_"));
    if let Ok(val) = std::env::var(&alt_var) {
        return Ok(val);
    }

    if let Ok(val) = std::env::var("DOTENV_PASS") {
        return Ok(val);
    }

    let pass_file = format!("{}.pass", file_stem);
    if Path::new(&pass_file).exists()
        && let Ok(val) = fs::read_to_string(&pass_file) {
            return Ok(val.trim().to_string());
        }

    if Path::new(".env.pass").exists()
        && let Ok(val) = fs::read_to_string(".env.pass") {
            return Ok(val.trim().to_string());
        }

    Err(anyhow!(
        "No encryption password found. Provide --password argument or set $DOTENV_PASS environment variable."
    ))
}

pub fn encrypt_env_file(input_file: &Path, output_file: Option<&Path>, password: Option<&str>) -> Result<PathBuf> {
    let content = Zeroizing::new(fs::read_to_string(input_file)?);
    let file_name = input_file.to_string_lossy().to_string();
    let pwd = Zeroizing::new(get_encryption_password(&file_name, password)?);

    let mut salt = [0u8; 16];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut aes_gcm::aead::OsRng, &mut salt);
    let key = Zeroizing::new(crate::wallet::derive_key(&pwd, &salt)?);

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("key init failed"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, content.as_bytes())
        .map_err(|_| anyhow!("encryption failed"))?;

    let payload = format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    );

    let target_path = match output_file {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(format!("{}.enc", input_file.display())),
    };

    write_secure_file(&target_path, payload.as_bytes())?;
    Ok(target_path)
}

pub fn decrypt_env_file(input_file: &Path, output_file: Option<&Path>, password: Option<&str>) -> Result<PathBuf> {
    let payload = fs::read_to_string(input_file)?;
    let file_name = input_file.to_string_lossy().to_string();
    let clean_name = file_name.trim_end_matches(".enc").trim_end_matches(".encrypted");
    let pwd = Zeroizing::new(get_encryption_password(clean_name, password)?);

    let parts: Vec<&str> = payload.trim().split(':').collect();
    let (key, nonce_b64, cipher_b64) = if parts.len() == 3 {
        let salt = BASE64_STANDARD.decode(parts[0]).map_err(|_| anyhow!("Invalid salt"))?;
        let key = Zeroizing::new(crate::wallet::derive_key(&pwd, &salt)?);
        (key, parts[1], parts[2])
    } else if parts.len() == 2 {
        let key = Zeroizing::new(derive_pass_key(&pwd));
        (key, parts[0], parts[1])
    } else {
        return Err(anyhow!("Invalid encrypted payload format"));
    };

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("key init failed"))?;
    let nonce_bytes = BASE64_STANDARD.decode(nonce_b64).map_err(|_| anyhow!("Invalid nonce"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher_bytes = BASE64_STANDARD.decode(cipher_b64).map_err(|_| anyhow!("Invalid cipher text"))?;

    let plain_bytes = Zeroizing::new(
        cipher
            .decrypt(nonce, cipher_bytes.as_ref())
            .map_err(|_| anyhow!("Decryption failed. Check your password."))?,
    );
    let plain_str = Zeroizing::new(String::from_utf8(plain_bytes.to_vec())?);

    let target_path = match output_file {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(clean_name),
    };

    write_secure_file(&target_path, plain_str.as_bytes())?;
    Ok(target_path)
}

pub fn load_and_parse_env(env_path: &Path, password: Option<&str>) -> Result<BTreeMap<String, String>> {
    let file_str = env_path.to_string_lossy();
    if file_str.ends_with(".enc") || file_str.ends_with(".encrypted") {
        let payload = fs::read_to_string(env_path)?;
        let clean_name = file_str.trim_end_matches(".enc").trim_end_matches(".encrypted");
        let pwd = get_encryption_password(clean_name, password)?;

        let parts: Vec<&str> = payload.trim().split(':').collect();
        let (key, nonce_b64, cipher_b64) = if parts.len() == 3 {
            let salt = BASE64_STANDARD.decode(parts[0]).map_err(|_| anyhow!("Invalid salt"))?;
            let key = crate::wallet::derive_key(&pwd, &salt)?;
            (key, parts[1], parts[2])
        } else if parts.len() == 2 {
            let key = derive_pass_key(&pwd);
            (key, parts[0], parts[1])
        } else {
            return Err(anyhow!("Invalid encrypted payload format"));
        };

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("key init failed"))?;
        let nonce_bytes = BASE64_STANDARD.decode(nonce_b64)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher_bytes = BASE64_STANDARD.decode(cipher_b64)?;
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
    password: Option<&str>,
) -> Result<i32> {
    if command_and_args.is_empty() {
        return Err(anyhow!("No command provided. Usage: bsec run -- <command>"));
    }

    let mut env_map = BTreeMap::new();
    // Keeps any `run --secret` staging dir alive until the child exits; its Drop wipes it.
    let mut _staged_guard: Option<crate::materialize::StagedDir> = None;

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
        let user_addr = crate::wallet::get_wallet_info(password)?.address.clone();
        // One decrypt / one on-chain read, then decide: stage files or inject vars.
        let payload = crate::secrets::view_payload(sec_id, &user_addr, password)?;
        match crate::materialize::stage_and_envs(&payload)? {
            Some((staged, envs)) => {
                _staged_guard = Some(staged);
                env_map.extend(envs);
            }
            None => {
                let vars = if payload.content.trim_start().starts_with('{') {
                    parse_json_content(&payload.content)?
                } else {
                    parse_env_content(&payload.content)
                };
                env_map.extend(vars);
            }
        }
    }

    if let Some(file_path) = target_env_file {
        if file_path.exists() {
            let file_vars = load_and_parse_env(file_path, password)?;
            env_map.extend(file_vars);
        }
    } else if target_secret_id.is_none() {
        let default_local = Path::new(".env.local");
        if default_local.exists() {
            let file_vars = load_and_parse_env(default_local, password)?;
            env_map.extend(file_vars);
        } else {
            let default_env = Path::new(".env");
            if default_env.exists() {
                let file_vars = load_and_parse_env(default_env, password)?;
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
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            Ok(code)
        } else if let Some(sig) = status.signal() {
            Ok(128 + sig)
        } else {
            Ok(1)
        }
    }
    #[cfg(not(unix))]
    {
        Ok(status.code().unwrap_or(1))
    }
}
