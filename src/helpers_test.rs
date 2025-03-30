#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_find_matches() {
        // Test with a match
        let mut output = Vec::new();
        find_matches("line one\nline two\nline three", "two", &mut output);
        assert_eq!(String::from_utf8(output).unwrap(), "line two\n");

        // Test with multiple matches
        let mut output = Vec::new();
        find_matches("apple\nbanana\napple pie", "apple", &mut output);
        assert_eq!(String::from_utf8(output).unwrap(), "apple\napple pie\n");

        // Test with no matches
        let mut output = Vec::new();
        find_matches("apple\nbanana\norange", "grape", &mut output);
        assert_eq!(String::from_utf8(output).unwrap(), "");
    }

    #[test]
    fn test_search_file() {
        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "This is line one").unwrap();
        writeln!(temp_file, "This is line two").unwrap();
        writeln!(temp_file, "This is line three").unwrap();

        // Capture stdout
        let path = temp_file.path().to_path_buf();

        // This is harder to test directly since it writes to stdout
        // In a real test, you might want to refactor search_file to return the matches
        // or accept a writer parameter like find_matches does

        // For now, we'll just ensure it doesn't panic
        search_file(&path, "line two");
    }

    #[test]
    fn test_log() {
        // This is mostly testing that the function doesn't panic
        // In a real test, you might want to capture the log output
        let result = log();
        assert!(result.is_ok());
    }

    // TODO: look into proptest and fuzzer crates
    #[test]
    fn check_answer_validity() {
        assert_eq!(lib::answer(), 42);
    }

    #[test]
    fn file_doesnt_exist() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("clienv")?;

        cmd.arg("foobar").arg("test/file/doesnt/exist");
        cmd.assert()
            .failure()
            .stderr(prdicate::str::contains("could not read file"));

        Ok(())
    }

    // find required pattern
    #[test]
    fn find_content_in_file() -> Result<(), Box<dyn std::error::Error>> {
        let file = assert_fs::NamedTempFile::new("sample.txt")?;
        file.write_str("A test\nActual content\nMore content\nAnother test")?;

        let mut cmd = Command::cargo_bin("clienv")?;
        cmd.arg("test").arg(file.path());
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("A test\nAnother test"));

        Ok(())
    }

    // for an empty string pattern
    #[test]
    fn find_content_in_file() -> Result<(), Box<dyn std::error::Error>> {
        let file = assert_fs::NamedTempFile::new("sample.txt")?;
        file.write_str("A test\nActual content\nMore content\nAnother test")?;

        let mut cmd = Command::cargo_bin("clienv")?;
        cmd.arg("test").arg(file.path());
        cmd.assert().success().stdout(predicate::str::contains(""));

        Ok(())
    }

    #[test]
    fn find_a_match() {
        let mut result = Vec::new();
        lib::find_matches("lorem ipsum\ndolor sit here", "lorem", &mut result);
        assert_eq!(result, b"lorem ipsum\n");
    }
}
