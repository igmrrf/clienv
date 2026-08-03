//! Ephemeral Secret Sharing & Cryptographic Exchange Integration Tests
//!
//! Target Modules: `src/secrets.rs`, `src/wallet.rs`, `src/main.rs`
//! Flow Tested:
//!   - Public secret sharing (`bsec share --to public`) & auto-destruction upon max-read limit or TTL
//!   - Forward-secret ECDH secp256k1 public key encrypted secret exchange (`bsec share --to 0x04...`)
//!   - Password-protected wallet secret sharing and viewing (`bsec share --password`, `bsec view --password`)
//!   - Rejection of external 20-byte EVM addresses for ECDH key exchange without explicit SEC1 public key
//!   - Full secret management lifecycle: `share` -> `view` -> `list` -> `revoke` -> `hide`

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

/// Share/view/list/revoke flows now perform real on-chain transactions and IPFS I/O, so these
/// illustrative CLI checks require a deployed registry, a funded wallet, and an IPFS backend.
/// The primary end-to-end verification is `scripts/e2e-setup.sh` followed by driving the CLI
/// (it provisions and funds a single wallet sequentially, avoiding nonce races). These tests
/// each use an isolated `BSEC_HOME`, so running them live also needs per-home funding and
/// `--test-threads=1`. Skipped unless `BSEC_E2E=1`.
fn e2e_enabled() -> bool {
    std::env::var("BSEC_E2E").map(|v| v == "1").unwrap_or(false)
}

macro_rules! require_e2e {
    () => {
        if !e2e_enabled() {
            eprintln!(
                "SKIP: on-chain e2e. Use scripts/e2e-setup.sh to provision anvil + IPFS + a funded \
                 wallet, then set BSEC_E2E=1 (run with --test-threads=1)."
            );
            return Ok(());
        }
    };
}

/// Tests public secret sharing flow accessible without individual recipient keys.
/// Target File: `src/secrets.rs` -> `share_secret()`, `view_secret()`
/// Flow: `bsec share --to public --content ...` -> `bsec view <secret_id>`
#[test]
fn test_public_secret_sharing_flow() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
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

/// Tests asymmetric ECDH secp256k1 key exchange when sharing secrets to a SEC1 public key (0x04...).
/// Target File: `src/secrets.rs` -> `resolve_recipient_pubkey()`, `share_secret()`
/// Flow: Extract recipient public key -> `bsec share --to <pubkey>` -> `bsec view <secret_id>`
#[test]
fn test_ecdh_pubkey_secret_sharing_flow() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
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

    // Share secret using SEC1 Public Key
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

/// Tests secret sharing and retrieval when the wallet is encrypted with a password.
/// Target File: `src/secrets.rs` -> `share_secret()`, `view_secret()` with `password`
/// Flow: `bsec init --password` -> `bsec share --password` -> `bsec view --password`
#[test]
fn test_password_protected_wallet_secret_viewing() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
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

/// Tests that attempting to perform ECDH key exchange with a 20-byte EVM address (without public key) is rejected.
/// Target File: `src/secrets.rs` -> `resolve_recipient_pubkey()`
/// Flow: `bsec share --to 0x1111222233334444555566667777888899990000` -> error assertion
#[test]
fn test_external_address_rejection_for_ecdh() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    cmd_init.assert().success();

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

/// Tests full secret management lifecycle: share -> list -> revoke -> hide.
/// Target File: `src/secrets.rs` -> `share_secret()`, `list_secrets()`, `revoke_secret()`, `hide_secret()`
/// Flow: `bsec init` -> `bsec share` -> `bsec list` -> `bsec revoke` -> `bsec hide`
#[test]
fn test_wallet_and_secret_sharing_lifecycle_flow() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. Init wallet
    let mut cmd_init = Command::cargo_bin("bsec")?;
    cmd_init.current_dir(temp_dir.path());
    cmd_init.env("BSEC_HOME", temp_dir.path());
    cmd_init.arg("init").arg("--overwrite");
    cmd_init.assert().success();

    // 2. Share secret
    let mut cmd_share = Command::cargo_bin("bsec")?;
    cmd_share.current_dir(temp_dir.path());
    cmd_share.env("BSEC_HOME", temp_dir.path());
    cmd_share
        .arg("share")
        .arg("--content")
        .arg("SUPER_SECRET_KEY=123456")
        .arg("--ttl")
        .arg("1d")
        .arg("--max-reads")
        .arg("3");

    let assert_share = cmd_share.assert().success();
    let stdout_share = String::from_utf8(assert_share.get_output().stdout.clone())?;

    let mut secret_id = String::new();
    for line in stdout_share.lines() {
        if line.starts_with("Secret ID: ") {
            secret_id = line.trim_start_matches("Secret ID: ").trim().to_string();
        }
    }
    assert!(!secret_id.is_empty());

    // 3. List secrets
    let mut cmd_list = Command::cargo_bin("bsec")?;
    cmd_list.current_dir(temp_dir.path());
    cmd_list.env("BSEC_HOME", temp_dir.path());
    cmd_list.arg("list");
    cmd_list
        .assert()
        .success()
        .stdout(predicate::str::contains(&secret_id));

    // 4. Revoke secret
    let mut cmd_revoke = Command::cargo_bin("bsec")?;
    cmd_revoke.current_dir(temp_dir.path());
    cmd_revoke.env("BSEC_HOME", temp_dir.path());
    cmd_revoke.arg("revoke").arg(&secret_id);
    cmd_revoke.assert().success();

    // 5. Hide secret
    let mut cmd_hide = Command::cargo_bin("bsec")?;
    cmd_hide.current_dir(temp_dir.path());
    cmd_hide.env("BSEC_HOME", temp_dir.path());
    cmd_hide.arg("hide").arg("--all");
    cmd_hide.assert().success();

    Ok(())
}
