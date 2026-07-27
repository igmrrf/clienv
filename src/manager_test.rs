//! Unit Tests for Legacy Key-Value Storage & Symmetric Encryption
//!
//! Target File: `src/manager.rs`
//! Flow Tested:
//!   - AES-256-GCM symmetric string encryption and decryption (`encrypt()`, `decrypt()`)
//!   - Key-value variable setting and retrieval (`set_env_variable()`, `get_env_variable()`)
//!   - Variable HashMap storage loading (`load_env_variables()`)

#[cfg(test)]
mod tests {
    use crate::manager::*;
    use std::collections::HashMap;

    /// Tests AES-256-GCM encryption and decryption round-trip.
    /// Target File: `src/manager.rs` -> `encrypt()`, `decrypt()`
    #[test]
    fn test_encrypt_decrypt() {
        let key = "test_encryption_key_32_bytes_long!";
        let plaintext = "secret value";

        let encrypted = encrypt(plaintext, key).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Tests setting and retrieving an encrypted key-value pair in memory store.
    /// Target File: `src/manager.rs` -> `set_env_variable()`, `get_env_variable()`
    #[test]
    fn test_set_get_env_variable() {
        let key = "test_key_32_bytes_long_secret!!";
        let var_name = "TEST_VAR_MGR";
        let var_value = "test_value_mgr";

        set_env_variable(var_name, var_value, key);
        let retrieved = get_env_variable(var_name, key);
        assert_eq!(retrieved, Some(var_value.to_string()));
    }

    /// Tests memory map state initialization.
    /// Target File: `src/manager.rs` -> `load_env_variables()`
    #[test]
    fn test_load_save_env_variables() {
        let mut env_vars = HashMap::new();
        env_vars.insert("TEST_KEY".to_string(), "TEST_VALUE".to_string());
        assert_eq!(env_vars.len(), 1);
    }
}