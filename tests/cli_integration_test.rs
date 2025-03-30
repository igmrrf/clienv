use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_cli_get_nonexistent_var() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("clienv")?;
    
    cmd.arg("get").arg("NONEXISTENT_VAR");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("environment variable not found"));
    
    Ok(())
}

#[test]
fn test_cli_set_and_get_var() -> Result<(), Box<dyn std::error::Error>> {
    let var_name = "TEST_CLI_VAR";
    let var_value = "test_value_123";
    
    // Set the variable
    let mut cmd = Command::cargo_bin("clienv")?;
    cmd.arg("set").arg(var_name).arg(var_value);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("environment variable set successfully"));
    
    // Get the variable
    let mut cmd = Command::cargo_bin("clienv")?;
    cmd.arg("get").arg(var_name);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(var_value));
    
    Ok(())
}

#[test]
fn test_cli_search() -> Result<(), Box<dyn std::error::Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str("A test line\nActual content\nMore content\nAnother test line")?;
    
    let mut cmd = Command::cargo_bin("clienv")?;
    cmd.arg("search").arg("test").arg("--path").arg(file.path());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("A test line")
                .and(predicate::str::contains("Another test line")));
    
    Ok(())
}

#[test]
fn test_cli_search_file_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("clienv")?;
    
    cmd.arg("search")
       .arg("pattern")
       .arg("--path")
       .arg("nonexistent/file/path.txt");
    
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("could not read file"));
    
    Ok(())
}