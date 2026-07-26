# Plan: BSEC Security & Implementation Fixes

Remediate security vulnerabilities, access control flaws, and implementation bugs across the `bsec` CLI application to establish production readiness.

## Scope

- **In**:
  - Replace homebrew password hashing with salted SHA-256 key derivation.
  - Expand wallet mnemonic generation to use standard 2048-word BIP39 dictionary for 128-bit entropy.
  - Enforce strict POSIX `0600` file permissions on sensitive files (`wallet.json`, `.env.pass`).
  - Eliminate `0x0000...0000` fallback identity in `src/main.rs`; require valid wallet authorization.
  - Fix `view_secret` read-count mutation order in `src/secrets.rs`.
  - Replace `.expect()` panics in `src/manager.rs` with proper `Result` error handling.
  - Remove dead code warnings and fix duplicate/invalid test functions in `src/helpers_test.rs`.
- **Out**:
  - Full remote network RPC/IPFS node integration (mocked/local testnet configuration remains).

## Action Items

- [x] **Step 1: Dependencies**: Add `sha2` crate to `Cargo.toml` for standard SHA-256 cryptographic hashing.
- [x] **Step 2: Cryptographic KDF**: Update `derive_key` / `hash_digest` in `src/wallet.rs`, `src/secrets.rs`, `src/env_file.rs`, and `src/manager.rs` to use salted SHA-256 key derivation.
- [x] **Step 3: Mnemonic Entropy**: Update `src/wallet.rs` mnemonic generator with full 2048-word BIP-39 wordlist and 128-bit random entropy.
- [x] **Step 4: Access Control Fix**: Remove zero-address (`0x0000...`) default fallbacks in `src/main.rs` and require active wallet authorization.
- [x] **Step 5: Secret Viewing Logic**: Refactor `view_secret` in `src/secrets.rs` to decrypt payload before mutating `read_count`.
- [x] **Step 6: Manager Panic Cleanup**: Refactor `src/manager.rs` to return `Result` and remove `.expect()` calls.
- [x] **Step 7: Dead Code & Test Fixes**: Remove unused functions and fix duplicated test names in `src/helpers_test.rs`.
- [x] **Step 8: File Permission Protection**: Add file permission restriction (POSIX `0600`) when writing wallet and secret files.
- [x] **Step 9: Verification**: Run `cargo test` and verify clean build with zero warnings and all tests passing.

## Open Questions

- None. All tasks completed and verified with `cargo test`.
