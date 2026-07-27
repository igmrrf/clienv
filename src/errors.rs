use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum BsecError {
    #[error("Wallet not found. Please run 'bsec init' first.")]
    WalletNotFound,

    #[error("Invalid password or wallet data corrupted.")]
    InvalidPassword,

    #[error("Secret with ID '{0}' not found.")]
    SecretNotFound(String),

    #[error("Secret has expired or maximum read count exceeded.")]
    SecretExpired,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid BIP-39 mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid recipient or public key: {0}")]
    InvalidRecipient(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Format parsing error: {0}")]
    ParseError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("{0}")]
    Generic(String),
}

impl BsecError {
    #[allow(dead_code)]
    pub fn exit_code(&self) -> i32 {
        match self {
            BsecError::InvalidPassword => 2,
            BsecError::SecretExpired
            | BsecError::SecretNotFound(_)
            | BsecError::PermissionDenied(_) => 3,
            BsecError::IoError(_) | BsecError::ParseError(_) | BsecError::ConfigError(_) => 4,
            BsecError::InvalidMnemonic(_) | BsecError::InvalidRecipient(_) => 5,
            _ => 1,
        }
    }
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, BsecError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_exit_codes() {
        assert_eq!(BsecError::InvalidPassword.exit_code(), 2);
        assert_eq!(BsecError::SecretExpired.exit_code(), 3);
        assert_eq!(BsecError::SecretNotFound("id".into()).exit_code(), 3);
        assert_eq!(BsecError::PermissionDenied("denied".into()).exit_code(), 3);
        assert_eq!(BsecError::ParseError("parse".into()).exit_code(), 4);
        assert_eq!(BsecError::ConfigError("cfg".into()).exit_code(), 4);
        assert_eq!(BsecError::InvalidMnemonic("mnem".into()).exit_code(), 5);
        assert_eq!(BsecError::InvalidRecipient("recip".into()).exit_code(), 5);
        assert_eq!(BsecError::WalletNotFound.exit_code(), 1);
        assert_eq!(BsecError::CryptoError("crypto".into()).exit_code(), 1);
        assert_eq!(BsecError::Generic("gen".into()).exit_code(), 1);
    }
}
