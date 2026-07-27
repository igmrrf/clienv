//! Wallet & Identity Management Integration Tests
//!
//! Target Modules: `src/wallet.rs`, `src/main.rs`, `src/errors.rs`
//! Flow Tested:
//!   - Wallet initialization from BIP-39 mnemonic phrases (`bsec init --import-mnemonic`)
//!   - Password-protected wallet initialization & info inspection (`bsec wallet info --password`)
//!   - Typed exit status code 2 verification on invalid wallet passwords

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

/// Tests wallet initialization from a known 12-word BIP-39 mnemonic phrase.
/// Target File: `src/wallet.rs` -> `init_wallet()`
/// Flow: `bsec init --import-mnemonic "<mnemonic>" --overwrite`
#[test]
fn test_wallet_init_mnemonic() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.env("BSEC_HOME", temp_dir.path());
    cmd.arg("init")
        .arg("--import-mnemonic")
        .arg(mnemonic)
        .arg("--overwrite");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wallet initialized successfully!"));

    Ok(())
}

/// Tests password-protected wallet creation and info command parsing.
/// Target File: `src/wallet.rs` -> `get_wallet_info()`
/// Flow: `bsec init --password <pass>` -> `bsec wallet info --password <pass>`
#[test]
fn test_password_protected_wallet_creation_and_info() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init
        .arg("init")
        .arg("--overwrite")
        .arg("--password")
        .arg("secret_wallet_pass_123");
    cmd_init.assert().success();

    let mut cmd_info = Command::cargo_bin("bsec")?;
    cmd_info.current_dir(temp_dir.path());
    cmd_info.env("BSEC_HOME", temp_dir.path());
    cmd_info
        .arg("wallet")
        .arg("info")
        .arg("--password")
        .arg("secret_wallet_pass_123");

    cmd_info
        .assert()
        .success()
        .stdout(predicate::str::contains("Wallet Information:"))
        .stdout(predicate::str::contains("Address:"));

    Ok(())
}

/// Tests typed exit code status 2 when an invalid password is provided to unlock a wallet.
/// Target File: `src/main.rs` -> `handle_cli_error()` & `src/errors.rs` -> `BsecError::InvalidPassword`
/// Flow: `bsec wallet info --password wrong_pass` -> asserts process exit code 2
#[test]
fn test_invalid_password_exit_code_2() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init
        .arg("init")
        .arg("--overwrite")
        .arg("--password")
        .arg("correct_pass");
    cmd_init.assert().success();

    let mut cmd_info = Command::cargo_bin("bsec")?;
    cmd_info.current_dir(temp_dir.path());
    cmd_info.env("BSEC_HOME", temp_dir.path());
    cmd_info
        .arg("wallet")
        .arg("info")
        .arg("--password")
        .arg("wrong_pass");

    cmd_info.assert().code(predicate::eq(2));

    Ok(())
}
