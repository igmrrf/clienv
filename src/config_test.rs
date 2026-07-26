#[cfg(test)]
mod tests {
    use crate::config::*;
    use std::env;

    #[test]
    fn test_config_defaults_and_override() {
        unsafe {
            env::remove_var("ENCRYPTION_KEY");
        }
        let config_default = Config::default();
        assert_eq!(config_default.encryption_key, "default_encryption_key");

        unsafe {
            env::set_var("ENCRYPTION_KEY", "test_key_123");
        }
        let config_custom = Config::default();
        assert_eq!(config_custom.encryption_key, "test_key_123");

        unsafe {
            env::remove_var("ENCRYPTION_KEY");
        }
    }

    #[test]
    fn test_get_config() {
        let config = get_config();
        assert!(!config.encryption_key.is_empty());
    }
}
