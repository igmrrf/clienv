//! Unit Tests for Application Global Configuration
//!
//! Target File: `src/config.rs`
//! Flow Tested:
//!   - `Config::default()` resolution and `ENCRYPTION_KEY` environment variable override
//!   - `get_config()` confy configuration loader fallback

#[cfg(test)]
mod tests {
    use crate::config::*;
    use std::env;

    /// Tests default encryption key fallbacks and custom ENCRYPTION_KEY environment overrides.
    /// Target File: `src/config.rs` -> `Config::default()`
    #[test]
    fn test_config_defaults_and_override() {
        unsafe {
            env::remove_var("ENCRYPTION_KEY");
        }
        let config_default = Config::default();
        assert!(!config_default.encryption_key.is_empty());

        unsafe {
            env::set_var("ENCRYPTION_KEY", "test_key_123");
        }
        let config_custom = Config::default();
        assert_eq!(config_custom.encryption_key, "test_key_123");

        unsafe {
            env::remove_var("ENCRYPTION_KEY");
        }
    }

    /// Tests loading configuration via confy.
    /// Target File: `src/config.rs` -> `get_config()`
    #[test]
    fn test_get_config() {
        let config = get_config();
        assert!(!config.encryption_key.is_empty());
    }
}

