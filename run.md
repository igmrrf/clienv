# BSEC Application Running Guide

This guide details how to run the `bsec` CLI application in both **Local File Mode** and **On-Chain Blockchain Mode** across various local, testnet, and mainnet EVM environments.

---

## 🎯 Dual Execution Modes Overview

`bsec` supports two complementary operating modes depending on your workflow:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                 BSEC CLI                                 │
└────────────────────┬─────────────────────────────────┬───────────────────┘
                     │                                 │
                     ▼                                 ▼
      ┌─────────────────────────────┐   ┌─────────────────────────────┐
      │     1. Local File Mode      │   │ 2. On-Chain Blockchain Mode │
      ├─────────────────────────────┤   ├─────────────────────────────┤
      │ • Offline .env conversions  │   │ • On-Chain Secret Sharing   │
      │ • Schema validation         │   │ • Immutable msg.sender Auth │
      │ • File-level AES encryption │   │ • Decentralized IPFS CIDs   │
      │ • In-memory process injection│   │ • On-Chain Revocation       │
      └─────────────────────────────┘   └─────────────────────────────┘
```

---

## ⚙️ Building & Installation

```bash
# Clone repository
git clone https://github.com/igmrrf/bsec.git
cd bsec

# Build release binary
cargo build --release

# Add binary to path or run directly
./target/release/bsec --help
```

---

## 💻 Mode 1: Local File Mode Execution

Local File Mode operates completely offline without needing a blockchain connection or network access. It is ideal for local environment management, format conversions, `.env` file encryption, and process environment variable injection.

### 1. Wallet & Key Generation

```bash
# Initialize a new local wallet (mnemonic + keypair)
bsec init

# Initialize with password protection
bsec init --password "MySecretPassphrase123"

# Import wallet from existing 12-word mnemonic
bsec init --import-mnemonic "abandon ability able about above absent absorb abstract absurd abuse access accident"

# View wallet address & public key details
bsec wallet info
```

### 2. Local Ephemeral Secret Sharing

```bash
# Share secret text (expires in 24h by default, 1 max read)
bsec share --content "super_secret_api_key_99"

# Share secret to your public key with custom TTL and max reads limit
bsec share --content "db_password_xyz" --to 0x04abc... --ttl 2h --max-reads 3

# View secret (auto-destructs upon reaching max reads or expiry)
bsec view <secret_id>

# Save decrypted content directly to a file
bsec view <secret_id> --output decrypted_config.txt

# List active or expired secrets
bsec list --active
bsec list --expired

# Revoke a shared secret
bsec revoke <secret_id>
```

### 3. Process Environment Injection (`bsec run`)

Inject variables into process memory without writing unencrypted secrets to disk:

```bash
# Run command with environment variables injected from .env.local
bsec run -- npm run dev

# Run command with injected secret from shared secret ID
bsec run --secret <secret_id> -- python app.py

# Run command with custom password-protected file
bsec run -e .env.prod.enc --password "my_pass" -- node server.js
```

### 4. Format Conversions & Utilities

```bash
# Convert JSON to .env format
bsec convert config.json .env.local --format env

# Convert with custom prefix
bsec convert config.json .env.local --prefix "NEXT_PUBLIC_"

# Embed JavaScript object properties
bsec convert config.json config.js --embed "VUE_APP_"
```

### 5. Schema Validation & Templates

```bash
# Validate .env against .env.schema (auto-populates missing keys)
bsec validate -e .env.local -s .env.schema

# Generate .env.template from .env
bsec generate -e .env -o .env.template

# Inspect single environment variable value
bsec log DATABASE_URL -f .env.local
```

### 6. File-Level AES-256-GCM Encryption

```bash
# Encrypt .env file with password
bsec encrypt .env -o .env.enc --password "secure_password"

# Decrypt encrypted file
bsec decrypt .env.enc -o .env.dec --password "secure_password"
```

---

## 🌐 Mode 2: On-Chain Blockchain Mode Execution

On-Chain Mode connects to an EVM blockchain node and an IPFS gateway. Secret access rules, read counters, expiration dates, and sender identities (`msg.sender`) are verified 100% on-chain.

### Step 1: Start Local EVM & IPFS Environment

Spin up the local Anvil EVM node (port `8545`) and local IPFS node (port `5001`/`8080`):

```bash
docker compose up -d
```

Verify docker containers:

```bash
docker compose ps
```

---

### Step 2: Configure Network Environment

Display current network configuration:

```bash
bsec config --show
```

Switch network profiles:

```bash
# Connect to local Docker Anvil node (Chain ID 31337)
bsec config --network local

# Connect to Polygon Amoy Testnet (Chain ID 80002)
bsec config --network amoy

# Connect to Ethereum Sepolia Testnet (Chain ID 11155111)
bsec config --network sepolia

# Connect to Base Sepolia Testnet (Chain ID 84532)
bsec config --network base-sepolia

# Custom Network and RPC URL
bsec config --network custom --rpc "https://my-custom-rpc-endpoint.com"
```

---

### Step 3: Blockchain Execution Commands

#### 1. Share Secret On-Chain

When sharing a secret on-chain:
1. `bsec` encrypts the content locally (AES-256-GCM + SEC1 ECDH).
2. `bsec` uploads the ciphertext to IPFS (returning IPFS CID `Qm...`).
3. `bsec` sends a transaction to the [`BsecSecretRegistry`](file:///Users/igmrrf/Desktop/tmp/bsec/contracts/BsecSecretRegistry.sol) smart contract recording `msg.sender`, recipient, `ipfsCid`, `expiresAt`, and `maxReads`.

```bash
bsec share --content "API_SECRET=live_key_xyz" --to 0x04abc... --ttl 7d --max-reads 5
```

#### 2. View Secret On-Chain

`bsec` queries the smart contract to verify `msg.sender`, checks expiration and read counts, fetches the ciphertext from IPFS, and decrypts it locally:

```bash
bsec view <secret_id>
```

#### 3. Revoke Secret On-Chain

Sends an on-chain transaction calling `revokeSecret(secretId)` on the smart contract:

```bash
bsec revoke <secret_id>
```

---

## 🔗 Network Configuration Reference

| Network | Chain ID | Command | Default RPC Endpoint | Faucets / Explorer |
| :--- | :---: | :--- | :--- | :--- |
| **Local Anvil Node** | `31337` | `bsec config --network local` | `http://localhost:8545` | Auto Pre-Funded (10,000 ETH) |
| **Polygon Amoy** | `80002` | `bsec config --network amoy` | `https://rpc-amoy.polygon.technology` | • <https://faucet.polygon.technology/> |
| **Ethereum Sepolia**| `11155111`| `bsec config --network sepolia` | `https://rpc.sepolia.org` | • <https://sepoliafaucet.com/> |
| **Base Sepolia** | `84532` | `bsec config --network base-sepolia`| `https://sepolia.base.org` | • <https://faucets.chain.link/base-sepolia> |
| **Polygon Mainnet** | `137` | `bsec config --network polygon` | `https://polygon-rpc.com` | • <https://polygonscan.com/> |
| **Base Mainnet** | `8453` | `bsec config --network base` | `https://mainnet.base.org` | • <https://basescan.org/> |
