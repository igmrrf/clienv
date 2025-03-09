use assert_cmd::prelude::*; // add methods on commands
use predicates::prelude::*; // used for writing assertions
use std::process::Command; // run programs
use assert_fs::prelude::*; // create temp file
mod lib;


// TODO: look into proptest and fuzzer crates
#[test]
fn check_answer_validity(){
    assert_eq!(lib::answer(), 42);
}

#[test]
fn file_doesnt_exist()-> Result<(), Box<dyn std::error::Error>>{
    let mut cmd = Command::cargo_bin("clienv")?;

    cmd.arg("foobar").arg("test/file/doesnt/exist");
    cmd.assert().failure().stderr(prdicate::str::contains("could not read file"));

    Ok(())
}

// find required pattern
#[test]
fn find_content_in_file() -> Result<(), Box<dyn std::error:Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str("A test\nActual content\nMore content\nAnother test")?;

    let mut cmd = Command::cargo_bin("clienv")?;
    cmd.arg("test").arg(file.path());
    cmd.assert().success().stdout(predicate::str::contains("A test\nAnother test"));

    Ok(())
}


// for an empty string pattern
#[test]
fn find_content_in_file() -> Result<(), Box<dyn std::error:Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str("A test\nActual content\nMore content\nAnother test")?;

    let mut cmd = Command::cargo_bin("clienv")?;
    cmd.arg("test").arg(file.path());
    cmd.assert().success().stdout(predicate::str::contains(""));

    Ok(())
}

#[test]
fn find_a_match(){
    let mut result = Vec::new();
    lib::find_matches("lorem ipsum\ndolor sit here", "lorem", &mut result)
    assert_eq!(result,b"lorem ipsum\n");
}
