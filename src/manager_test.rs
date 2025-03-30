#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use std::env;

    #[test]
    fn test_encrypt_decrypt() {
        let key = "test_encryption_key_32_bytes_long!";
        let plaintext = "secret value";
        
        let encrypted = encrypt(plaintext, key);
        assert_ne!(encrypted, plaintext); // Encryption should change the value
        
        let decrypted = decrypt(&encrypted, key);
        assert_eq!(decrypted, plaintext); // Decryption should restore original value
    }

    #[test]
    fn test_set_get_env_variable() {
        let key = "test_encryption_key_32_bytes_long!";
        let var_name = "TEST_VAR";
        let var_value = "test_value";
        
        // First ensure the variable doesn't exist
        {
            let env_vars = ENV_VARS.lock().unwrap();
            assert!(!env_vars.contains_key(var_name));
        }
        
        // Set the variable
        set_env_variable(var_name, var_value, key);
        
        // Verify it was set and encrypted
        {
            let env_vars = ENV_VARS.lock().unwrap();
            assert!(env_vars.contains_key(var_name));
            let encrypted_value = env_vars.get(var_name).unwrap();
            assert_ne!(encrypted_value, var_value); // Value should be encrypted
        }
        
        // Get the variable and verify decryption
        let retrieved = get_env_variable(var_name, key);
        assert_eq!(retrieved, Some(var_value.to_string()));
        
        // Clean up
        {
            let mut env_vars = ENV_VARS.lock().unwrap();
            env_vars.remove(var_name);
            save_env_variables(&env_vars);
        }
    }

    #[test]
    fn test_load_save_env_variables() {
        // Create a temporary directory for testing
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("env_vars.json");
        
        // Change to the temporary directory
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(dir.path()).unwrap();
        
        // Test with a new environment
        let mut env_vars = HashMap::new();
        env_vars.insert("TEST_KEY".to_string(), "TEST_VALUE".to_string());
        
        // Save the variables
        save_env_variables(&env_vars);
        
        // Verify the file was created
        assert!(file_path.exists());
        
        // Load the variables
        let loaded_vars = load_env_variables();
        
        // Verify the loaded variables match what we saved
        assert_eq!(loaded_vars.len(), 1);
        assert_eq!(loaded_vars.get("TEST_KEY"), Some(&"TEST_VALUE".to_string()));
        
        // Clean up
        env::set_current_dir(original_dir).unwrap();
        dir.close().unwrap();
    }
}