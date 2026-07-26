# CLIENV

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
- ⚡ **Built-in Fast Storage**: Simple encrypted key-value store (`set`, `get`) and pattern search (`search`).

---

## Installation

```bash
# Build from source
cargo build --release

# Run binary
./target/release/clienv --help
```

---

## Usage Guide

### 1. Wallet & Identity Management

```bash
# Initialize a new wallet
clienv init

# Initialize with password protection
clienv init --password "your_password"

# Import an existing wallet from mnemonic
clienv init --import-mnemonic "word1 word2 ... word12"

# View wallet details
clienv wallet info
```

### 2. Process Environment Injection (`clienv run`)

```bash
# Run command with environment variables injected from .env.local (default)
clienv run -- npm run dev

# Run command with injected environment variables from a custom or encrypted file
clienv run -e .env.prod.enc -- python app.py
```

### 3. Secret Sharing & Ephemeral Storage

```bash
# Share secret text (expires in 24h by default, 1 max read)
clienv share --content "my-secret-api-key"

# Share secret with custom TTL and max reads limit
clienv share --content "database-password" --ttl 1h --max-reads 5 --to 0x123...

# Share secret from file
clienv share --file secret.txt --ttl 7d

# View a secret (auto-destructs upon reaching max reads or expiry)
clienv view <secret_id>

# Save decrypted secret directly to a file
clienv view <secret_id> --output decrypted.txt

# List active or expired secrets
clienv list --active
clienv list --expired

# Revoke a shared secret immediately
clienv revoke <secret_id>

# Hide secret(s)
clienv hide <secret_id>
```

### 4. Network Configuration

```bash
# Display current network configuration
clienv config --show

# Configure network (polygon, base, amoy, sepolia, base-sepolia, local)
clienv config --network amoy

# Set custom network and RPC endpoint
clienv config --network sepolia --rpc "https://rpc.sepolia.org"
```

### 5. Testnets & Free Faucets Guide

For team development, testing, or zero-cost execution, configure `clienv` to use a testnet or local node:

| Network | Chain ID | `clienv` Network Flag | Free Token Faucet Links |
| :--- | :---: | :--- | :--- |
| **Polygon Amoy Testnet** | `80002` | `clienv config --network amoy` | • <https://faucet.polygon.technology/> |
| **Ethereum Sepolia Testnet** | `11155111` | `clienv config --network sepolia` | • <https://sepoliafaucet.com/><br>• <https://sepolia-faucet.pk910.de/><br>• <https://faucets.chain.link/> |
| **Base Sepolia Testnet** | `84532` | `clienv config --network base-sepolia` | • <https://www.bwarelabs.com/faucets/base-sepolia><br>• <https://faucets.chain.link/base-sepolia> |
| **Local Docker Compose Node** | `31337` | `clienv config --network local` | • **Auto Pre-Funded** (10,000 test ETH on `docker compose up`) |

#### Using Local Docker Testnet

```bash
# Spin up local EVM node (Anvil) & IPFS gateway in Docker
docker compose up -d

# Switch clienv to local testnet
clienv config --network local
```

### 6. Format Conversion & Utilities

```bash
# Convert JSON to .env format
clienv convert config.json .env.local --format env

# Convert with prefix
clienv convert config.json .env.local --prefix "NEXT_PUBLIC_"

# Embed JavaScript object properties
clienv convert config.json config.js --embed "VUE_APP_"
```

### 7. Schema Validation & Templates

```bash
# Validate .env.local against .env.schema
clienv validate -e .env.local -s .env.schema

# Generate .env.template from existing .env file
clienv generate -e .env -o .env.template

# Inspect single environment variable value
clienv log MONGO_URL -f .env.local
```

### 8. File-Level Encryption

```bash
# Set encryption key
echo "my_secure_password" > .env.pass

# Encrypt .env file
clienv encrypt .env -o .env.enc

# Decrypt .env.enc file
clienv decrypt .env.enc -o .env.dec
```

### 9. Legacy Key-Value Storage

```bash
# Store encrypted key-value pair
clienv set MONGO_URI "mongodb://localhost:27017"

# Retrieve key-value pair
clienv get MONGO_URI

# Search for pattern in file
clienv search "API_KEY" --path .env
```

---

## Authors & Acknowledgments

- <https://github.com/fuyutarow/convert-json-env.git>
- <https://github.com/nathanagez/env-cli>
- <https://github.com/jaydenwindle/senv>
- <https://github.com/chempogonzalez/dotenv-checker>
