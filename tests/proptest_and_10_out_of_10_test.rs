use assert_cmd::Command;
use proptest::prelude::*;
use tempfile::TempDir;

#[test]
fn test_shell_completion_generation() {
    let mut cmd = Command::cargo_bin("bsec").unwrap();
    let assert = cmd.arg("completion").arg("zsh").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(output.contains("#compdef bsec"));
}

#[test]
fn test_shell_completion_bash() {
    let mut cmd = Command::cargo_bin("bsec").unwrap();
    let assert = cmd.arg("completion").arg("bash").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(output.contains("_bsec()"));
}

#[test]
fn test_json_output_flags() {
    let temp_dir = TempDir::new().unwrap();
    let bsec_home = temp_dir.path().to_path_buf();

    // 1. Init wallet
    let mut init_cmd = Command::cargo_bin("bsec").unwrap();
    init_cmd
        .env("BSEC_HOME", &bsec_home)
        .arg("init")
        .assert()
        .success();

    // 2. Wallet info --json
    let mut info_cmd = Command::cargo_bin("bsec").unwrap();
    let info_assert = info_cmd
        .env("BSEC_HOME", &bsec_home)
        .arg("wallet")
        .arg("info")
        .arg("--json")
        .assert()
        .success();
    let info_stdout = String::from_utf8(info_assert.get_output().stdout.clone()).unwrap();
    assert!(info_stdout.contains("\"address\""));
    assert!(info_stdout.contains("\"public_key\""));

    // 3. Config --show --json
    let mut config_cmd = Command::cargo_bin("bsec").unwrap();
    let config_assert = config_cmd
        .env("BSEC_HOME", &bsec_home)
        .arg("config")
        .arg("--show")
        .arg("--json")
        .assert()
        .success();
    let config_stdout = String::from_utf8(config_assert.get_output().stdout.clone()).unwrap();
    assert!(config_stdout.contains("\"network\""));

    // 4. List --json
    let mut list_cmd = Command::cargo_bin("bsec").unwrap();
    let list_assert = list_cmd
        .env("BSEC_HOME", &bsec_home)
        .arg("list")
        .arg("--json")
        .assert()
        .success();
    let list_stdout = String::from_utf8(list_assert.get_output().stdout.clone()).unwrap();
    assert!(list_stdout.starts_with('['));
}

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
