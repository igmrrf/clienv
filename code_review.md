# BSEC Code Review & Security Audit Report

**Target Project**: `bsec` (Rust CLI for secret management & environment variables)  
**Date**: July 26, 2026  
**Scope**: Implementation correctness, security & cryptographic audit, production readiness.

---

## Executive Summary

`bsec` provides a clean and versatile feature set for managing environment files (`.env`, `JSON`, `YAML`), process environment injection (`bsec run`), schema validation, file encryption, and ephemeral secret sharing. 

However, **critical security vulnerabilities** exist in custom cryptographic functions, password key derivation, entropy generation for mnemonics, file permissions, and CLI argument handling. Addressing these cryptographic and architectural issues is required before declaring production readiness.

---

## 1. Security & Cryptographic Audit

### 🚨 Critical Vulnerabilities

#### 1. Homebrew Hash & Insecure Key Derivation (KDF)
- **Files**: [`src/wallet.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/wallet.rs#L59-L76), [`src/secrets.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/secrets.rs#L57-L66), [`src/env_file.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/env_file.rs#L11-L20), [`src/manager.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/manager.rs#L27-L36)
- **Issue**: Passwords are formatted into 32-byte encryption keys using a custom non-standard hash function (`hash_digest` / `pad_or_hash_key`) using simple bit rotations and wrapping additions without salt or memory-hard iterations.
- **Risk**: Extremely vulnerable to fast GPU brute-force and dictionary attacks.
- **Remediation**: Use standard, well-tested KDFs such as **Argon2id** (`argon2` crate) or **PBKDF2-HMAC-SHA256** with a randomly generated 16-byte salt stored alongside the ciphertext.

#### 2. Non-Standard Mnemonic Generation & Low Entropy
- **File**: [`src/wallet.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/wallet.rs#L113-L128)
- **Issue**: Mnemonic phrases are sampled from a fixed array of only 25 words (`(b as usize) % word_list.len()`).
- **Risk**: 12 words chosen from 25 words yield only $\approx 55.9$ bits of entropy ($25^{12}$). Attackers can exhaustively search all possible wallet seed combinations in minutes. Additionally, it is incompatible with standard BIP39 wallets.
- **Remediation**: Replace custom word selection with standard BIP39 crates (e.g. `bip39` crate with 2048-word wordlists providing 128/256 bits of entropy).

#### 3. Default Zero-Address Access Control Bypass
- **File**: [`src/main.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/main.rs#L393-L397) (and L416-L418, L447-L449, L475-L477)
- **Issue**: When `wallet::get_wallet_info(None)` fails (e.g., when a wallet is encrypted or uninitialized), the application falls back to `0x0000000000000000000000000000000000000000`.
- **Risk**: Anyone running the CLI without an initialized or unlocked wallet automatically assumes identity `0x0000...0000` and can view, list, or revoke any secrets shared with or sent from that zero address.
- **Remediation**: Require an explicit unlocked identity/wallet address for access-controlled operations instead of falling back to a dummy address.

#### 4. Plaintext Password Leakage via CLI Flags
- **File**: [`src/main.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/main.rs#L38)
- **Issue**: Accepting sensitive passwords via command-line flags (e.g., `--password "my_secret"`) leaks them to process listing commands (`ps aux`) and shell history logs (`.bash_history`).
- **Remediation**: Prompt interactively for passwords via `rpassword` or read from environment variables / standard input.

---

## 2. Implementation Correctness & Code Quality

### ⚠️ Bugs & Edge Cases

1. **State Corruption on Failed Decryption in `view_secret`**
   - **File**: [`src/secrets.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/secrets.rs#L168-L176)
   - **Issue**: `record.read_count += 1` is executed **before** calling `decrypt_text`. If decryption fails due to a corrupted payload or invalid key, the read count is still consumed.
   - **Fix**: Perform decryption first; increment and persist `read_count` only after successful decryption.

2. **Panics on Untrusted Input in `manager.rs`**
   - **File**: [`src/manager.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/manager.rs#L63-L76)
   - **Issue**: `manager::decrypt` calls `.expect("invalid nonce")`, `.expect("invalid cipher_text")`, `.expect("decryption failed")`, and `.expect("invalid UTF-8 sequence")`.
   - **Fix**: Replace `.expect(...)` calls with `Result<String, Error>` handling to prevent CLI panics when encountering invalid input data.

3. **Compiler Warnings & Broken Helper Tests**
   - **File**: [`src/helpers_test.rs`](file:///Users/igmrrf/Desktop/tmp/bsec/src/helpers_test.rs)
   - **Issue**: 
     - Function `find_content_in_file` is defined twice in the test module.
     - Reference to `lib::answer()` which is not defined.
     - Unused helper functions `log()`, `load_env_variables()`, and `save_project_config()`.
   - **Fix**: Remove duplicated/obsolete tests and resolve unused function warnings or annotate with `#[allow(dead_code)]`.

---

## 3. Production Readiness & Architectural Guidance

### 🛠️ Key Recommendations

1. **Strict File Permissions (POSIX 0600)**
   - Wallet files (`~/.bsec/wallet.json`), secret storage, and `.env.pass` files should be created with restricted file permissions (`0600` on Unix systems via `std::os::unix::fs::PermissionsExt`).

2. **Atomic File Storage**
   - Direct `fs::write` calls can corrupt files if the CLI process is killed or interrupted mid-write. Use atomic write mechanisms (write to a temporary file in the same directory and rename atomically).

3. **Sensitive Memory Sanitization**
   - Key material, passwords, and decrypted secret contents stored in RAM should be zeroed upon drop using the `zeroize` crate to prevent memory leaks in swap or core dumps.

4. **Structured Error Output**
   - Standardize CLI error formatting across commands and support `--json` output flags for CI/CD pipeline automation.

---

## Action Plan Checklist

- [ ] Replace `hash_digest` / `pad_or_hash_key` with **Argon2id** key derivation.
- [ ] Migrate `generate_mnemonic` to standard **BIP39** implementation.
- [ ] Remove fallback to zero-address (`0x0000...`) in `src/main.rs`.
- [ ] Replace `.expect()` panics in `src/manager.rs` with `Result` handling.
- [ ] Implement POSIX `0600` file permission enforcement for sensitive wallet and secret files.
- [ ] Clean up unused functions and test warnings in `src/helpers_test.rs`.
