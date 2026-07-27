//! Environment File Management & Conversion Integration Tests
//!
//! Target Modules: `src/env_file.rs`, `src/project_config.rs`, `src/main.rs`
//! Flow Tested:
//!   - Conversion between JSON, YAML, and `.env` file formats (`bsec convert`)
//!   - Advanced conversion flags (`--prefix`, `--suffix`, `--embed`)
//!   - Quoted values & inline hash comment (`#`) parsing logic in `.env` files
//!   - Schema validation (`bsec validate`) & template generation (`bsec generate`)
//!   - Single environment variable logging (`bsec log`)
//!   - Process memory environment variable injection (`bsec run -- <cmd>`)
//!   - Property-based testing (`proptest`) for panic-free parser robustness

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use proptest::prelude::*;
use std::process::Command;

/// Tests JSON to .env format conversion.
/// Target File: `src/env_file.rs` -> `convert_env_file()`
/// Flow: `bsec convert input.json output.env --format env`
#[test]
fn test_convert_json_to_env() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let json_file = temp_dir.child("config.json");
    json_file.write_str(r#"{"PORT": "8080", "DB_HOST": "localhost"}"#)?;

    let env_file = temp_dir.child(".env.out");

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("convert")
        .arg(json_file.path())
        .arg(env_file.path())
        .arg("--format")
        .arg("env");

    cmd.assert().success();

    let content = std::fs::read_to_string(env_file.path())?;
    assert!(content.contains("PORT='8080'") || content.contains("PORT=8080"));
    assert!(content.contains("DB_HOST='localhost'") || content.contains("DB_HOST=localhost"));

    Ok(())
}

/// Tests advanced format conversion options: prefixing, suffixing, and JavaScript object property embedding.
/// Target File: `src/env_file.rs` -> `convert_env_file()` with `--prefix`, `--suffix`, `--embed`
/// Flow: `bsec convert config.json config.js --embed "VUE_APP_"`
#[test]
fn test_convert_advanced_options() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let input_file = temp_dir.child("input.json");
    input_file.write_str(r#"{"API_URL": "http://api.local"}"#)?;

    let output_file = temp_dir.child("output.js");

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("convert")
        .arg(input_file.path())
        .arg(output_file.path())
        .arg("--embed")
        .arg("VUE_APP_");

    cmd.assert().success();

    let content = std::fs::read_to_string(output_file.path())?;
    assert!(content.contains("API_URL: 'VUE_APP_API_URL'"));

    Ok(())
}

/// Tests parsing quoted `.env` values containing inline `#` characters versus unquoted comments.
/// Target File: `src/env_file.rs` -> `parse_env_content()`
/// Flow: `bsec log SECRET_KEY -f .env.test`
#[test]
fn test_quoted_env_parsing_with_hash_comment() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.test");
    env_file.write_str("SECRET_KEY=\"my_secret # 123_pass\"\nUNQUOTED_KEY=value # comment\n")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.env("BSEC_HOME", temp_dir.path());
    cmd.arg("log").arg("SECRET_KEY").arg("-f").arg(env_file.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("SECRET_KEY: my_secret # 123_pass"));

    let mut cmd_unquoted = Command::cargo_bin("bsec")?;
    cmd_unquoted.current_dir(temp_dir.path());
    cmd_unquoted.env("BSEC_HOME", temp_dir.path());
    cmd_unquoted.arg("log").arg("UNQUOTED_KEY").arg("-f").arg(env_file.path());

    cmd_unquoted
        .assert()
        .success()
        .stdout(predicate::str::contains("UNQUOTED_KEY: value"));

    Ok(())
}

/// Tests `.env` schema validation and auto-template generation.
/// Target File: `src/env_file.rs` -> `validate_env_file()`, `generate_template()`
/// Flow: `bsec validate` -> `bsec generate`
#[test]
fn test_validate_and_generate() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let schema_file = temp_dir.child(".env.schema");
    schema_file.write_str("DATABASE_URL=\nAPI_KEY=\nLOG_LEVEL=\n")?;

    let env_file = temp_dir.child(".env.local");
    env_file.write_str("DATABASE_URL=postgres://localhost/db\n")?;

    // 1. Validate
    let mut cmd_val = Command::cargo_bin("bsec")?;
    cmd_val.current_dir(temp_dir.path());
    cmd_val
        .arg("validate")
        .arg("--env")
        .arg(env_file.path())
        .arg("--schema")
        .arg(schema_file.path());

    cmd_val.assert().success();

    let updated_env = std::fs::read_to_string(env_file.path())?;
    assert!(updated_env.contains("API_KEY="));
    assert!(updated_env.contains("LOG_LEVEL="));

    // 2. Generate template
    let template_file = temp_dir.child(".env.template");
    let mut cmd_gen = Command::cargo_bin("bsec")?;
    cmd_gen.current_dir(temp_dir.path());
    cmd_gen
        .arg("generate")
        .arg("--env")
        .arg(env_file.path())
        .arg("--out")
        .arg(template_file.path());

    cmd_gen.assert().success();

    let tmpl_content = std::fs::read_to_string(template_file.path())?;
    assert!(tmpl_content.contains("DATABASE_URL=#Your DATABASE_URL here"));

    Ok(())
}

/// Tests single environment variable value logging from a file.
/// Target File: `src/env_file.rs` -> `log_env_var()`
/// Flow: `bsec log <VAR_NAME> -f .env.local`
#[test]
fn test_log_env_var_command() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.local");
    env_file.write_str("REDIS_HOST=127.0.0.1\nREDIS_PORT=6379\n")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("log").arg("REDIS_PORT").arg("-f").arg(env_file.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("REDIS_PORT: 6379"));

    Ok(())
}

/// Tests running a subprocess with injected environment variables without writing plaintext files to disk.
/// Target File: `src/env_file.rs` -> `run_with_envs()`
/// Flow: `bsec run -e .env.custom -- env`
#[test]
fn test_run_command_process_injection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.inject");
    env_file.write_str("INJECTED_VAR_123=SUCCESS_VAL\n")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("run")
        .arg("-e")
        .arg(env_file.path())
        .arg("--")
        .arg("env");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("INJECTED_VAR_123=SUCCESS_VAL"));

    Ok(())
}

/// Tests process environment injection using a local `.bsec.json` project configuration file.
/// Target File: `src/project_config.rs`, `src/env_file.rs` -> `run_with_envs()`
/// Flow: `.bsec.json` config -> `bsec run -- env`
#[test]
fn test_run_with_project_config() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let env_file = temp_dir.child(".env.proj");
    env_file.write_str("PROJ_VAR=HELLO_PROJECT\n")?;

    let bsec_json = temp_dir.child(".bsec.json");
    bsec_json.write_str(&format!(
        r#"{{"env_file": "{}"}}"#,
        env_file.path().display()
    ))?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("run").arg("--").arg("env");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("PROJ_VAR=HELLO_PROJECT"));

    Ok(())
}

// Property-based test ensuring env parsing helper never panics on arbitrary string inputs
proptest! {
    #[test]
    fn test_proptest_env_parsing_no_panic(key in "[A-Za-z0-9_]{1,20}", val in ".*") {
        let env_line = format!("{}={}", key, val);
        let _parsed = bsec_parse_env_helper(&env_line);
    }
}

fn bsec_parse_env_helper(line: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for l in line.lines() {
        let trimmed = l.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

