#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        // Ensure any existing env var doesn't interfere
        env::remove_var("ENCRYPTION_KEY");

        let config = Config::default();
        assert_eq!(config.encryption_key, "default_encryption_key");
    }

    #[test]
    fn test_config_with_env_var() {
        // Set the environment variable
        env::set_var("ENCRYPTION_KEY", "test_key_123");

        let config = Config::default();
        assert_eq!(config.encryption_key, "test_key_123");

        // Clean up
        env::remove_var("ENCRYPTION_KEY");
    }

    #[test]
    fn test_get_config() {
        // This is more of an integration test, but we can at least verify it returns something
        let config = get_config();
        assert!(!config.encryption_key.is_empty());
    }
}
