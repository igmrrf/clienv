//! File-Level Encryption & Decryption Integration Tests
//!
//! Target Modules: `src/env_file.rs`, `src/wallet.rs`, `src/main.rs`
//! Flow Tested:
//!   - End-to-end `.env` file encryption and decryption using `.env.pass` key files
//!   - File encryption (`bsec encrypt`) & decryption (`bsec decrypt`) using explicit `--password` CLI flags
//!   - Enforcing restricted `0o600` permissions (`rw-------`) on decrypted `.env` output files

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use std::process::Command;

/// Tests file-level encryption and decryption using password files (.env.pass).
/// Target File: `src/env_file.rs` -> `encrypt_env_file()`, `decrypt_env_file()`
/// Flow: `echo <pass> > .env.pass` -> `bsec encrypt .env` -> `bsec decrypt .env.enc`
#[test]
fn test_file_encrypt_decrypt_with_pass_file() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let pass_file = temp_dir.child(".env.pass");
    pass_file.write_str("my_secret_encryption_password\n")?;

    let env_file = temp_dir.child(".env");
    env_file.write_str("SECRET_API_KEY=1234567890\n")?;

    // 1. Encrypt
    let mut cmd_enc = Command::cargo_bin("bsec")?;
    cmd_enc.current_dir(temp_dir.path());
    cmd_enc.arg("encrypt").arg(env_file.path());
    cmd_enc.assert().success();

    let enc_path = temp_dir.path().join(".env.enc");
    assert!(enc_path.exists());

    // 2. Decrypt
    let dec_path = temp_dir.path().join(".env.dec");
    let mut cmd_dec = Command::cargo_bin("bsec")?;
    cmd_dec.current_dir(temp_dir.path());
    cmd_dec
        .arg("decrypt")
        .arg(&enc_path)
        .arg("--out")
        .arg(&dec_path);

    cmd_dec.assert().success();

    let decrypted_content = std::fs::read_to_string(dec_path)?;
    assert_eq!(decrypted_content, "SECRET_API_KEY=1234567890\n");

    Ok(())
}

/// Tests file-level encryption and decryption using explicit `--password` command-line flags.
/// Target File: `src/env_file.rs` -> `encrypt_env_file()`, `decrypt_env_file()` with `--password`
/// Flow: `bsec encrypt .env --password <pass>` -> `bsec decrypt .env.enc --password <pass>`
#[test]
fn test_file_encryption_decryption_with_cli_password() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.secret");
    env_file.write_str("DB_PASS=super_secret_db_password\n")?;

    let enc_file = temp_dir.child(".env.secret.enc");
    let dec_file = temp_dir.child(".env.secret.dec");

    // Encrypt with --password flag
    let mut cmd_enc = Command::cargo_bin("bsec")?;
    cmd_enc.env("BSEC_HOME", temp_dir.path());
    cmd_enc
        .arg("encrypt")
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
    cmd_dec
        .arg("decrypt")
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

/// Tests that decrypted output files are written with restricted 0o600 (owner-only rw) permissions on UNIX platforms.
/// Target File: `src/env_file.rs` -> `decrypt_env_file()` with `write_secure_file()`
/// Flow: `bsec decrypt` -> metadata mode inspection (`permissions.mode() & 0o777 == 0o600`)
#[cfg(unix)]
#[test]
fn test_decrypted_file_permissions() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.test_perm");
    env_file.write_str("API_KEY=test_key_123\n")?;

    let enc_file = temp_dir.child(".env.test_perm.enc");
    let dec_file = temp_dir.child(".env.test_perm.dec");

    // 1. Encrypt
    let mut cmd_enc = Command::cargo_bin("bsec")?;
    cmd_enc.env("BSEC_HOME", temp_dir.path());
    cmd_enc
        .arg("encrypt")
        .arg(env_file.path())
        .arg("--out")
        .arg(enc_file.path())
        .arg("--password")
        .arg("test_pass_perm");
    cmd_enc.assert().success();

    // 2. Decrypt
    let mut cmd_dec = Command::cargo_bin("bsec")?;
    cmd_dec.env("BSEC_HOME", temp_dir.path());
    cmd_dec
        .arg("decrypt")
        .arg(enc_file.path())
        .arg("--out")
        .arg(dec_file.path())
        .arg("--password")
        .arg("test_pass_perm");
    cmd_dec.assert().success();

    // 3. Verify file permissions are 0o600
    let metadata = std::fs::metadata(dec_file.path())?;
    let permissions = metadata.permissions();
    assert_eq!(permissions.mode() & 0o777, 0o600);

    Ok(())
}
