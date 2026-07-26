use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_wallet_and_secret_sharing_flow() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. Initialize wallet
    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    let assert_init = cmd_init.assert().success();
    let stdout_init = String::from_utf8(assert_init.get_output().stdout.clone())?;
    assert!(stdout_init.contains("Wallet initialized successfully!"));

    // Extract wallet address
    let mut wallet_addr = String::new();
    for line in stdout_init.lines() {
        if line.starts_with("Address: ") {
            wallet_addr = line.trim_start_matches("Address: ").trim().to_string();
        }
    }
    assert!(!wallet_addr.is_empty());

    // 2. View Wallet Info
    let mut cmd_info = Command::cargo_bin("bsec")?;
    cmd_info.current_dir(temp_dir.path());
    cmd_info.arg("wallet").arg("info");
    cmd_info
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallet Information:"))
        .stdout(predicate::str::contains(&wallet_addr));

    // 3. Share a secret to self
    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share
        .arg("share")
        .arg("--content")
        .arg("super_secret_payload_123")
        .arg("--to")
        .arg(&wallet_addr)
        .arg("--ttl")
        .arg("1h")
        .arg("--max-reads")
        .arg("2");
    
    let assert_share = cmd_share.assert().success();
    let stdout_share = String::from_utf8(assert_share.get_output().stdout.clone())?;
    assert!(stdout_share.contains("Secret shared successfully!"));

    let mut secret_id = String::new();
    for line in stdout_share.lines() {
        if line.starts_with("Secret ID: ") {
            secret_id = line.trim_start_matches("Secret ID: ").trim().to_string();
        }
    }
    assert!(!secret_id.is_empty());

    // 4. List Active Secrets
    let mut cmd_list = Command::cargo_bin("bsec")?;
    cmd_list.current_dir(temp_dir.path());
    cmd_list.arg("list").arg("--active");
    cmd_list
        .assert()
        .success()
        .stdout(predicate::str::contains(&secret_id));

    // 5. View Secret (1st read)
    let mut cmd_view1 = Command::cargo_bin("bsec")?;
    cmd_view1.current_dir(temp_dir.path());
    cmd_view1.arg("view").arg(&secret_id);
    cmd_view1
        .assert()
        .success()
        .stdout(predicate::str::contains("super_secret_payload_123"));

    // 6. Hide secret
    let mut cmd_hide = Command::cargo_bin("bsec")?;
    cmd_hide.current_dir(temp_dir.path());
    cmd_hide.arg("hide").arg(&secret_id);
    cmd_hide
        .assert()
        .success()
        .stdout(predicate::str::contains("Hidden 1 secret(s)."));

    Ok(())
}

#[test]
fn test_network_config_flow() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // Update config to amoy
    let mut cmd_cfg = Command::cargo_bin("bsec")?;
    cmd_cfg.current_dir(temp_dir.path());
    cmd_cfg.arg("config").arg("--network").arg("amoy");
    cmd_cfg
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration updated: Network = amoy"));

    // Show config
    let mut cmd_show = Command::cargo_bin("bsec")?;
    cmd_show.current_dir(temp_dir.path());
    cmd_show.arg("config").arg("--show");
    cmd_show
        .assert()
        .success()
        .stdout(predicate::str::contains("Network: amoy"))
        .stdout(predicate::str::contains("Chain ID: 80002"));

    Ok(())
}

#[test]
fn test_convert_advanced_options() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let input_json = temp_dir.child("config.json");
    input_json.write_str(r#"{"API_KEY": "xyz123", "PORT": "3000"}"#)?;
    let output_file = temp_dir.child("config.js");

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("convert")
        .arg("--file")
        .arg(input_json.path())
        .arg("--out")
        .arg(output_file.path())
        .arg("--prefix")
        .arg("VUE_APP_")
        .arg("--embed")
        .arg("ENV_VAR_");

    cmd.assert().success();

    let content = std::fs::read_to_string(output_file.path())?;
    assert!(content.contains("VUE_APP_API_KEY: 'ENV_VAR_VUE_APP_API_KEY'"));

    Ok(())
}

#[test]
fn test_log_env_var_command() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.local");
    env_file.write_str("DATABASE_URL=postgres://localhost:5432/mydb\n")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("log").arg("DATABASE_URL").arg("-f").arg(env_file.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("DATABASE_URL: postgres://localhost:5432/mydb"));

    Ok(())
}
