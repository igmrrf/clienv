#[cfg(test)]
mod tests {
    use crate::helpers::*;
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
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "This is line one").unwrap();
        writeln!(temp_file, "This is line two").unwrap();
        writeln!(temp_file, "This is line three").unwrap();

        let path = temp_file.path().to_path_buf();
        search_file(&path, "line two");
    }

    #[test]
    fn test_log() {
        let result = log();
        assert!(result.is_ok());
    }
}
