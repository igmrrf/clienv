# BSEC

A powerful, high-performance CLI tool written in Rust for secure, decentralized environment variable management, file encryption, format conversion, schema validation, process environment injection, and secret sharing.

---

## Key Features

- 🔒 **Blockchain & Wallet Management**: Wallet generation (`init`), mnemonic recovery, password protection, and public address management.
- 👥 **Ephemeral Secret Sharing**: Share encrypted secrets with configurable time-to-live (`--ttl`), maximum read limits (`--max-reads`), retrieval (`view`), listing (`list`), revocation (`revoke`), and hiding (`hide`).
- 🚀 **Process Environment Injection**: Run commands (`run -- <command>`) with secrets injected directly into process memory without creating plaintext files on disk.
- 🔄 **Format Conversion**: Convert between `.env`, `JSON`, and `YAML` files with support for custom prefixes (`--prefix`), suffixes (`--suffix`), and JavaScript object embedding (`--embed`).
- 📝 **Schema Validation & Templates**: Validate `.env` files against `.env.schema`, auto-fix missing keys, and generate `.env.template` files (`generate`).
- 🔐 **End-to-End File Encryption**: Encrypt (`encrypt`) and decrypt (`decrypt`) `.env` files using `$DOTENV_PASS`, `$DOTENV_<ENV>_PASS`, or `.env.pass` files.
- 📋 **Environment Variable Logging**: Inspect single variable values (`log`).
- 🔎 **Pattern Search**: Substring search within files (`search`).

---

## Security Model & Limitations

Read this before relying on `bsec` for sensitive data.

- **Confidentiality is cryptographic; access controls are advisory.** Secret payloads are
  encrypted with AES-256-GCM under a per-secret random key, which is wrapped for the
  recipient via ECDH (secp256k1) + HKDF-SHA256. Only the holder of the recipient private key
  can decrypt. The on-chain `expiresAt`, `maxReads`, and `revoked` fields gate *listing and
  the recorded read count* — they do **not** cryptographically prevent a recipient who has
  already fetched the IPFS payload from decrypting it again offline. Treat TTL / max-reads /
  revocation as best-effort lifecycle signals, not hard guarantees against a past recipient.
- **`--to public` provides no confidentiality.** Public secrets are wrapped with a fixed,
  well-known key so anyone can read them. Use it only for non-sensitive content.
- **Real backends required.** `share`/`view` perform real on-chain transactions (a funded
  wallet + deployed `BsecSecretRegistry`) and real IPFS storage (a Pinata JWT or a reachable
  IPFS daemon). With no backend reachable, commands fail with a clear error — they never fake
  success. See `scripts/e2e-setup.sh` for a local anvil + IPFS stack.
- **Wallet at rest.** Always create wallets with `--password` (Argon2id + AES-256-GCM).
  Without a password the private key and mnemonic are stored unencrypted (mode 0600) and
  `init` prints a warning.

---

## Installation

```bash
# Build from source
cargo build --release

# Run binary
./target/release/bsec --help
```

---

## 🚀 Deployment & Distribution Guides

For platform-specific installation and deployment flows, see the [Documentation Index](file:///Users/igmrrf/Desktop/tmp/bsec/docs/README.md):

* 📦 **Cargo (crates.io)**: [`docs/cargo.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/cargo.md)
* 🍺 **Homebrew**: [`docs/homebrew.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/homebrew.md)
* 🖥️ **GitHub Binary Releases**: [`docs/binary_releases.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/binary_releases.md)
* 🐳 **Docker & GHCR**: [`docs/docker.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/docker.md)
* 🐧 **Linux Packages (.deb, .rpm, AUR, snap)**: [`docs/linux_packages.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/linux_packages.md)
* 🪟 **Windows Packages (winget, choco, scoop)**: [`docs/windows_packages.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/windows_packages.md)
* 🟢 **NPM / NPX Engine**: [`docs/npm.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/npm.md)
* ⛓️ **Smart Contracts & EVM**: [`docs/smart_contracts.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/smart_contracts.md)

---

## Usage Guide

### 1. Wallet & Identity Management

```bash
# Initialize a new wallet
bsec init

# Initialize with password protection
bsec init --password "your_password"

# Import an existing wallet from mnemonic
bsec init --import-mnemonic "word1 word2 ... word12"

# View wallet details
bsec wallet info
```

### 2. Process Environment Injection (`bsec run`)

```bash
# Run command with environment variables injected from .env.local (default)
bsec run -- npm run dev

# Run command with injected environment variables from a custom or encrypted file
bsec run -e .env.prod.enc -- python app.py
```

### 3. Secret Sharing & Ephemeral Storage

```bash
# Share secret text (expires in 24h by default, 1 max read)
bsec share --content "my-secret-api-key"

# Share secret with custom TTL and max reads limit
bsec share --content "database-password" --ttl 1h --max-reads 5 --to 0x123...

# Share secret from file
bsec share --file secret.txt --ttl 7d

# View a secret (auto-destructs upon reaching max reads or expiry)
bsec view <secret_id>

# Save decrypted secret directly to a file
bsec view <secret_id> --output decrypted.txt

# List active or expired secrets
bsec list --active
bsec list --expired

# Revoke a shared secret immediately
bsec revoke <secret_id>

# Hide secret(s)
bsec hide <secret_id>
```

### 4. Network Configuration

```bash
# Display current network configuration
bsec config --show

# Configure network (polygon, base, amoy, sepolia, base-sepolia, local)
bsec config --network amoy

# Set custom network and RPC endpoint
bsec config --network sepolia --rpc "https://rpc.sepolia.org"
```

### 5. Testnets & Free Faucets Guide

For team development, testing, or zero-cost execution, configure `bsec` to use a testnet or local node:

| Network | Chain ID | `bsec` Network Flag | Free Token Faucet Links |
| :--- | :---: | :--- | :--- |
| **Polygon Amoy Testnet** | `80002` | `bsec config --network amoy` | • <https://faucet.polygon.technology/> |
| **Ethereum Sepolia Testnet** | `11155111` | `bsec config --network sepolia` | • <https://sepoliafaucet.com/><br>• <https://sepolia-faucet.pk910.de/><br>• <https://faucets.chain.link/> |
| **Base Sepolia Testnet** | `84532` | `bsec config --network base-sepolia` | • <https://www.bwarelabs.com/faucets/base-sepolia><br>• <https://faucets.chain.link/base-sepolia> |
| **Local Docker Compose Node** | `31337` | `bsec config --network local` | • **Auto Pre-Funded** (10,000 test ETH on `docker compose up`) |

#### Using Local Docker Testnet

```bash
# Spin up local EVM node (Anvil) & IPFS gateway in Docker
docker compose up -d

# Switch bsec to local testnet
bsec config --network local
```

### 6. Format Conversion & Utilities

```bash
# Convert JSON to .env format
bsec convert config.json .env.local --format env

# Convert with prefix
bsec convert config.json .env.local --prefix "NEXT_PUBLIC_"

# Embed JavaScript object properties
bsec convert config.json config.js --embed "VUE_APP_"
```

### 7. Schema Validation & Templates

```bash
# Validate .env.local against .env.schema
bsec validate -e .env.local -s .env.schema

# Generate .env.template from existing .env file
bsec generate -e .env -o .env.template

# Inspect single environment variable value
bsec log MONGO_URL -f .env.local
```

### 8. File-Level Encryption

```bash
# Set encryption key
echo "my_secure_password" > .env.pass

# Encrypt .env file
bsec encrypt .env -o .env.enc

# Decrypt .env.enc file
bsec decrypt .env.enc -o .env.dec
```

### 9. Legacy Key-Value Storage

```bash
# Store encrypted key-value pair
bsec set MONGO_URI "mongodb://localhost:27017"

# Retrieve key-value pair
bsec get MONGO_URI

# Search for pattern in file
bsec search "API_KEY" --path .env
```

---

## Authors & Acknowledgments

- <https://github.com/fuyutarow/convert-json-env.git>
- <https://github.com/nathanagez/env-cli>
- <https://github.com/jaydenwindle/senv>
- <https://github.com/chempogonzalez/dotenv-checker>
