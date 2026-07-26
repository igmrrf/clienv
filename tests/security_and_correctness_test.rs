use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_public_secret_sharing_flow() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. User A initializes wallet
    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    cmd_init.assert().success();

    // 2. User A shares a public secret
    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share
        .arg("share")
        .arg("--content")
        .arg("public_community_announcement_999")
        .arg("--to")
        .arg("public")
        .arg("--ttl")
        .arg("1h")
        .arg("--max-reads")
        .arg("5");

    let assert_share = cmd_share.assert().success();
    let stdout_share = String::from_utf8(assert_share.get_output().stdout.clone())?;

    let mut secret_id = String::new();
    for line in stdout_share.lines() {
        if line.starts_with("Secret ID: ") {
            secret_id = line.trim_start_matches("Secret ID: ").trim().to_string();
        }
    }
    assert!(!secret_id.is_empty());

    // 3. View public secret
    let mut cmd_view = Command::cargo_bin("bsec")?;
    cmd_view.current_dir(temp_dir.path());
    cmd_view.arg("view").arg(&secret_id);
    cmd_view
        .assert()
        .success()
        .stdout(predicate::str::contains("public_community_announcement_999"));

    Ok(())
}

#[test]
fn test_password_protected_wallet_secret_viewing() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. Initialize wallet with password "secret_pwd_123"
    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init
        .arg("init")
        .arg("--overwrite")
        .arg("--password")
        .arg("secret_pwd_123");
    cmd_init.assert().success();

    // 2. Share secret to self
    let mut cmd_info = Command::cargo_bin("bsec")?;
    cmd_info.current_dir(temp_dir.path());
    cmd_info.arg("wallet").arg("info").arg("--password").arg("secret_pwd_123");
    let assert_info = cmd_info.assert().success();
    let stdout_info = String::from_utf8(assert_info.get_output().stdout.clone())?;

    let mut wallet_addr = String::new();
    for line in stdout_info.lines() {
        if line.starts_with("Address: ") {
            wallet_addr = line.trim_start_matches("Address: ").trim().to_string();
        }
    }

    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share
        .arg("share")
        .arg("--content")
        .arg("pwd_protected_secret")
        .arg("--to")
        .arg(&wallet_addr)
        .arg("--password")
        .arg("secret_pwd_123")
        .arg("--ttl")
        .arg("1h");

    let assert_share = cmd_share.assert().success();
    let stdout_share = String::from_utf8(assert_share.get_output().stdout.clone())?;

    let mut secret_id = String::new();
    for line in stdout_share.lines() {
        if line.starts_with("Secret ID: ") {
            secret_id = line.trim_start_matches("Secret ID: ").trim().to_string();
        }
    }
    assert!(!secret_id.is_empty());

    // 3. View secret providing password
    let mut cmd_view = Command::cargo_bin("bsec")?;
    cmd_view.current_dir(temp_dir.path());
    cmd_view
        .arg("view")
        .arg(&secret_id)
        .arg("--password")
        .arg("secret_pwd_123");
    cmd_view
        .assert()
        .success()
        .stdout(predicate::str::contains("pwd_protected_secret"));

    Ok(())
}
