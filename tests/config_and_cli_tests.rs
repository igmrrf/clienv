//! Network Configuration, Legacy Store, Shell Completion & CLI Utilities Integration Tests
//!
//! Target Modules: `src/network_config.rs`, `src/helpers.rs`, `src/errors.rs`, `src/main.rs`
//! Flow Tested:
//!   - Blockchain & storage network configuration management (`bsec config --network`, `--rpc`, `--show`)
//!   - Substring pattern search within text files (`bsec search`)
//!   - Shell completion generation (`bsec completion <shell>`) for bash, zsh, fish, powershell
//!   - Help banner (`bsec --help`) & JSON format flags (`--json`)
//!   - Process exit code status 1 handling (`handle_cli_error`) on command failures

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command;

/// Tests network and RPC configuration querying and updates.
/// Target File: `src/network_config.rs` -> `update_network_config()`, `load_network_config()`
/// Flow: `bsec config --network amoy --rpc ...` -> `bsec config --show`
#[test]
fn test_network_config_flow() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. Update network config
    let mut cmd_update = Command::cargo_bin("bsec")?;
    cmd_update.current_dir(temp_dir.path());
    cmd_update.env("BSEC_HOME", temp_dir.path());
    cmd_update
        .arg("config")
        .arg("--network")
        .arg("amoy")
        .arg("--rpc")
        .arg("https://rpc-amoy.polygon.technology");

    cmd_update
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration updated: Network = amoy"));

    // 2. Show network config
    let mut cmd_show = Command::cargo_bin("bsec")?;
    cmd_show.current_dir(temp_dir.path());
    cmd_show.env("BSEC_HOME", temp_dir.path());
    cmd_show.arg("config").arg("--show");

    cmd_show
        .assert()
        .success()
        .stdout(predicate::str::contains("Network: amoy"))
        .stdout(predicate::str::contains("Chain ID: 80002"));

    Ok(())
}

/// Tests searching for text pattern matches in a file.
/// Target File: `src/helpers.rs` -> `search_file()`
/// Flow: `bsec search pattern --path sample.txt`
#[test]
fn test_cli_search() -> Result<(), Box<dyn std::error::Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str("A test line\nActual content\nMore content\nAnother test line")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("search").arg("test").arg("--path").arg(file.path());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("A test line")
                .and(predicate::str::contains("Another test line")));

    Ok(())
}

/// Tests searching in a non-existent file path returns non-zero error exit status.
/// Target File: `src/helpers.rs` -> `search_file()` error handling
/// Flow: `bsec search pattern --path nonexistent/file.txt`
#[test]
fn test_cli_search_file_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;

    cmd.arg("search")
        .arg("pattern")
        .arg("--path")
        .arg("nonexistent/file/path.txt");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("could not read file"));

    Ok(())
}

/// Tests CLI help banner output.
/// Target File: `src/main.rs` -> `Cli::command()` clap help
/// Flow: `bsec --help`
#[test]
fn test_cli_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ephemeral secret sharing"));

    Ok(())
}

/// Tests shell auto-completion generation for bash.
/// Target File: `src/main.rs` -> `Commands::Completion`
/// Flow: `bsec completion bash`
#[test]
fn test_shell_completion_bash() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("completion").arg("bash");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("_bsec"));

    Ok(())
}

/// Tests shell auto-completion generation across shells.
/// Target File: `src/main.rs` -> `clap_complete::generate()`
/// Flow: `bsec completion zsh`
#[test]
fn test_shell_completion_generation() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("completion").arg("zsh");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("#compdef bsec"));

    Ok(())
}

/// Tests --json output flag formatting across wallet info, config, and list subcommands.
/// Target File: `src/main.rs` -> `--json` output branches
/// Flow: `bsec wallet info --json`, `bsec config --show --json`, `bsec list --json`
#[test]
fn test_json_output_flags() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    // 1. Init wallet
    let mut init_cmd = Command::cargo_bin("bsec")?;
    init_cmd
        .env("BSEC_HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .arg("init")
        .arg("--overwrite")
        .assert()
        .success();

    // 2. Wallet info --json
    let mut info_cmd = Command::cargo_bin("bsec")?;
    let info_assert = info_cmd
        .env("BSEC_HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .arg("wallet")
        .arg("info")
        .arg("--json")
        .assert()
        .success();
    let info_stdout = String::from_utf8(info_assert.get_output().stdout.clone())?;
    assert!(info_stdout.contains("\"address\""));
    assert!(info_stdout.contains("\"public_key\""));

    // 3. Config --show --json
    let mut config_cmd = Command::cargo_bin("bsec")?;
    let config_assert = config_cmd
        .env("BSEC_HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .arg("config")
        .arg("--show")
        .arg("--json")
        .assert()
        .success();
    let config_stdout = String::from_utf8(config_assert.get_output().stdout.clone())?;
    assert!(config_stdout.contains("\"network\""));

    // 4. List --json
    let mut list_cmd = Command::cargo_bin("bsec")?;
    let list_assert = list_cmd
        .env("BSEC_HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .arg("list")
        .arg("--json")
        .assert()
        .success();
    let list_stdout = String::from_utf8(list_assert.get_output().stdout.clone())?;
    assert!(list_stdout.starts_with('['));

    Ok(())
}

/// Tests that command execution failure triggers a non-zero exit status.
/// Target File: `src/main.rs` -> `handle_cli_error()`
/// Flow: `bsec view invalid_secret_id_9999` -> asserts process failure exit code
#[test]
fn test_command_failure_exit_code_1() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.env("BSEC_HOME", temp_dir.path());
    cmd.arg("view").arg("invalid_secret_id_9999");
    cmd.assert().failure();

    Ok(())
}
