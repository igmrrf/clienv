# CLIENV - Blockchain-based Secret Sharing CLI Tool
Product Requirements Document (Rust Version)

## Overview
`clienv` is a decentralized, secure CLI tool written in Rust for environment variable management and ephemeral secret sharing. Each user has their own wallet for secure cryptographic interaction, asymmetric/symmetric encryption, and access management.

## Core Features

### 1. Wallet Management
- **Initialization**: `clienv init` generates a new wallet with mnemonic phrase, public/private keys, and optional password encryption.
- **Importing**: `clienv init --import-mnemonic "<mnemonic>"` restores an existing wallet.
- **Wallet Info**: `clienv wallet info` displays wallet public address, keys, and status.

### 2. Ephemeral Secret Sharing
- **Sharing**: `clienv share` encrypts secret content locally with AES-256-GCM, supporting configurable time-to-live (`--ttl`, e.g., `1m`, `2h`, `1d`, `7d`) and read limits (`--max-reads`).
- **Retrieval**: `clienv view <secret_id>` retrieves, verifies expiration/read limits, decrypts content, and auto-destructs the secret upon reaching read limits or TTL.
- **Listing**: `clienv list` filters active and expired shared secrets by status, recipient, or sender.
- **Revocation**: `clienv revoke <secret_id>` allows secret creators to immediately invalidate and delete a shared secret.
- **Hiding**: `clienv hide` hides specific secrets or user secret feeds.

### 3. Environment File Management
- **Format Conversion**: `clienv convert` transforms environment definitions between `.env`, `JSON`, and `YAML` formats, supporting custom prefixes (`--prefix`), suffixes (`--suffix`), and JavaScript object embedding (`--embed`).
- **Schema Validation**: `clienv validate` checks `.env` files against reference schema files (`.env.schema`) and auto-populates missing environment keys.
- **Template Generation**: `clienv generate` builds `.env.template` files from `.env` configurations.
- **Inspected Logging**: `clienv log` retrieves specific environment variable values from `.env` or `JSON` files.

### 4. File-Level Encryption
- **Encryption**: `clienv encrypt` encrypts `.env` files with AES-256-GCM using passwords from environment variables (`$DOTENV_PASS`, `$DOTENV_<ENV>_PASS`) or password files (`.env.pass`).
- **Decryption**: `clienv decrypt` restores encrypted environment files.

---

## Technical Architecture
- **Language**: Rust 2024 edition
- **CLI Parsing**: `clap` 4.5
- **Encryption**: AES-256-GCM, Base64
- **Serialization**: `serde`, `serde_json`, `serde_yaml`
- **File System / Config**: `confy`, `tempfile`
