use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_public_secret_sharing_flow() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. User A initializes wallet
    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    cmd_init.assert().success();

    // 2. User A shares a public secret
    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share.env("BSEC_HOME", temp_dir.path());
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
    cmd_view.env("BSEC_HOME", temp_dir.path());
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
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init
        .arg("init")
        .arg("--overwrite")
        .arg("--password")
        .arg("secret_pwd_123");
    cmd_init.assert().success();

    // 2. Share secret to self
    let mut cmd_info = Command::cargo_bin("bsec")?;
    cmd_info.current_dir(temp_dir.path());
    cmd_info.env("BSEC_HOME", temp_dir.path());
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
    cmd_share.env("BSEC_HOME", temp_dir.path());
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
    cmd_view.env("BSEC_HOME", temp_dir.path());
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

#[test]
fn test_ecdh_pubkey_secret_sharing_flow() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // Initialize wallet
    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    let assert_init = cmd_init.assert().success();
    let stdout_init = String::from_utf8(assert_init.get_output().stdout.clone())?;

    let mut pubkey = String::new();
    for line in stdout_init.lines() {
        if line.starts_with("Public Key: ") {
            pubkey = line.trim_start_matches("Public Key: ").trim().to_string();
        }
    }
    assert!(!pubkey.is_empty());

    // Share secret using Public Key
    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share.env("BSEC_HOME", temp_dir.path());
    cmd_share
        .arg("share")
        .arg("--content")
        .arg("ecdh_encrypted_payload_xyz")
        .arg("--to")
        .arg(&pubkey)
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

    // View secret addressed to public key
    let mut cmd_view = Command::cargo_bin("bsec")?;
    cmd_view.current_dir(temp_dir.path());
    cmd_view.env("BSEC_HOME", temp_dir.path());
    cmd_view.arg("view").arg(&secret_id);
    cmd_view
        .assert()
        .success()
        .stdout(predicate::str::contains("ecdh_encrypted_payload_xyz"));

    Ok(())
}

#[test]
fn test_external_address_rejection_for_ecdh() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    cmd_init.assert().success();

    // Try sharing to an external 42-char EVM address without public key
    let external_addr = "0x1111222233334444555566667777888899990000";
    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share.env("BSEC_HOME", temp_dir.path());
    cmd_share
        .arg("share")
        .arg("--content")
        .arg("test_content")
        .arg("--to")
        .arg(external_addr);

    cmd_share
        .assert()
        .stderr(predicate::str::contains("Recipient must be a valid SEC1 public key"));

    Ok(())
}

#[test]
fn test_quoted_env_parsing_with_hash_comment() -> Result<(), Box<dyn std::error::Error>> {
    use assert_fs::prelude::*;
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

#[test]
fn test_file_encryption_decryption_with_cli_password() -> Result<(), Box<dyn std::error::Error>> {
    use assert_fs::prelude::*;
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.secret");
    env_file.write_str("DB_PASS=super_secret_db_password\n")?;

    let enc_file = temp_dir.child(".env.secret.enc");
    let dec_file = temp_dir.child(".env.secret.dec");

    // Encrypt with --password flag
    let mut cmd_enc = Command::cargo_bin("bsec")?;
    cmd_enc.env("BSEC_HOME", temp_dir.path());
    cmd_enc.arg("encrypt")
        .arg(env_file.path())
        .arg("--out")
        .arg(enc_file.path())
        .arg("--password")
        .arg("my_cli_pass_123");
    cmd_enc.assert().success();

    assert!(enc_file.path().exists());

    // Decrypt with --password flag
    let mut cmd_dec = Command::cargo_bin("bsec")?;
    cmd_dec.env("BSEC_HOME", temp_dir.path());
    cmd_dec.arg("decrypt")
        .arg(enc_file.path())
        .arg("--out")
        .arg(dec_file.path())
        .arg("--password")
        .arg("my_cli_pass_123");
    cmd_dec.assert().success();

    let content = std::fs::read_to_string(dec_file.path())?;
    assert_eq!(content, "DB_PASS=super_secret_db_password\n");

    Ok(())
}
