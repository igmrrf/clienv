use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_cli_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ephemeral secret sharing"));
    Ok(())
}

#[test]
fn test_convert_json_to_env() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let input_json = temp_dir.child("config.json");
    input_json.write_str(r#"{"PORT": "8080", "DB_HOST": "localhost"}"#)?;
    let output_env = temp_dir.child(".env.out");

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("convert")
        .arg("--file")
        .arg(input_json.path())
        .arg("--out")
        .arg(output_env.path())
        .arg("--format")
        .arg("env");
    cmd.assert().success();

    let content = std::fs::read_to_string(output_env.path())?;
    assert!(content.contains("PORT='8080'"));
    assert!(content.contains("DB_HOST='localhost'"));

    Ok(())
}

#[test]
fn test_validate_and_generate() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env");
    env_file.write_str("API_KEY=secret_123\nDATABASE_URL=postgres://localhost\n")?;
    let template_file = temp_dir.child(".env.template");

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("generate")
        .arg("--env")
        .arg(env_file.path())
        .arg("--out")
        .arg(template_file.path());
    cmd.assert().success();

    let content = std::fs::read_to_string(template_file.path())?;
    assert!(content.contains("API_KEY=#Your API_KEY here"));
    assert!(content.contains("DATABASE_URL=#Your DATABASE_URL here"));

    Ok(())
}

#[test]
fn test_file_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.test");
    env_file.write_str("SECRET_TOKEN=super_secret_value\n")?;

    let pass_file = temp_dir.child(".env.test.pass");
    pass_file.write_str("testpassword123\n")?;

    let enc_file = temp_dir.child(".env.test.enc");
    let dec_file = temp_dir.child(".env.test.dec");

    // Encrypt
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.env("DOTENV_PASS", "testpassword123");
    cmd.arg("encrypt")
        .arg(env_file.path())
        .arg("--out")
        .arg(enc_file.path());
    cmd.assert().success();

    assert!(enc_file.path().exists());

    // Decrypt
    let mut cmd_dec = Command::cargo_bin("bsec")?;
    cmd_dec.env("DOTENV_PASS", "testpassword123");
    cmd_dec.arg("decrypt")
        .arg(enc_file.path())
        .arg("--out")
        .arg(dec_file.path());
    cmd_dec.assert().success();

    let decrypted_content = std::fs::read_to_string(dec_file.path())?;
    assert_eq!(decrypted_content, "SECRET_TOKEN=super_secret_value\n");

    Ok(())
}

#[test]
fn test_run_command_process_injection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let env_file = temp_dir.child(".env.run");
    env_file.write_str("INJECTED_TEST_VAR=hello_from_bsec\n")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("run")
        .arg("-e")
        .arg(env_file.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $INJECTED_TEST_VAR");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hello_from_bsec"));

    Ok(())
}

#[test]
fn test_run_with_project_config() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let proj_config = temp_dir.child(".bsec.json");
    proj_config.write_str(r#"{"env_file": ".env.proj"}"#)?;

    let env_file = temp_dir.child(".env.proj");
    env_file.write_str("PROJECT_ENV_KEY=project_value_123\n")?;

    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(temp_dir.path());
    cmd.arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $PROJECT_ENV_KEY");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("project_value_123"));

    Ok(())
}

#[test]
fn test_wallet_init_mnemonic() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.arg("init").arg("--overwrite");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Wallet initialized successfully!"));

    Ok(())
}
