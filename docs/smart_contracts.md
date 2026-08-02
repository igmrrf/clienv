# Smart Contract & EVM Deployment Guide

This document provides step-by-step instructions for compiling and deploying the **`BsecSecretRegistry`** smart contract across local testnets (Docker Anvil), EVM public testnets (Polygon Amoy, Ethereum Sepolia, Base Sepolia), EVM production mainnets, and IPFS nodes.

---

## 📋 Overview & Contract Architecture

The [`contracts/BsecSecretRegistry.sol`](file:///Users/igmrrf/Desktop/tmp/bsec/contracts/BsecSecretRegistry.sol) contract manages access rules, expiration timestamps, read counters, IPFS CIDs, and verified sender identities (`msg.sender`) on-chain.

### Key Contract Functions

| Function | Access | Description |
| :--- | :--- | :--- |
| `shareSecret(...)` | External | Registers a new encrypted secret, its IPFS CID, expiration, and read limits on-chain. |
| `recordRead(bytes32 id)` | External | Increments read count after verifying authorization, expiration, and limits. |
| `revokeSecret(bytes32 id)` | Sender Only | Immediately revokes access to a secret. |
| `getSecretInfo(bytes32 id)` | View | Returns complete on-chain secret metadata and status. |

---

## 🛠 Prerequisites & Setup

Install **Foundry** (which includes `forge` and `anvil`):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Verify `forge` installation:

```bash
forge --version
```

---

## 1. Deploying to Local Docker Testnet (Anvil)

### Step 1: Start Docker Containers

Spin up the local Anvil EVM node (port `8545`) and local IPFS node (ports `5001`/`8080`):

```bash
docker compose up -d
```

Check container status:

```bash
docker compose ps
```

### Step 2: Deploy Contract via Forge

Anvil pre-funds 10 test accounts with 10,000 ETH each. Use Account 0 private key for local deployment. `--broadcast` is required on recent Foundry to actually send the deploy transaction:

```bash
forge create contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

Note the `Deployed to: 0x...` address from the output — you need it in Step 3.

If you don't have Foundry installed on the host, run it from the Foundry image instead:

```bash
docker run --rm -v "$PWD/contracts:/contracts" \
  --add-host host.docker.internal:host-gateway ghcr.io/foundry-rs/foundry:latest \
  forge create /contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url http://host.docker.internal:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

### Step 3: Register the Deployed Address in `bsec`

Point `bsec` at the local node **and** the deployed registry address (from Step 2):

```bash
bsec config --network local \
  --rpc "http://localhost:8545" \
  --registry "0xYourDeployedRegistryAddress"
```

The local IPFS daemon at `http://127.0.0.1:5001` is used automatically (`ipfs.api_url`).

### Step 4: Create and Fund the `bsec` Wallet

`bsec` generates its own wallet, which is **separate** from Anvil's pre-funded accounts and
starts with a zero balance. On-chain writes (`share`, `view`, `revoke`) send real transactions,
so the wallet must hold native gas token. Create it, then fund it from Anvil Account 0:

```bash
# Create the wallet (add --password to encrypt at rest)
bsec init --overwrite

# Read the wallet address
WALLET=$(bsec wallet info | awk '/Address:/ {print $2}')

# Fund it with 10 ETH from Anvil Account 0
cast send "$WALLET" --value 10ether \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### Step 5: Verify End-to-End

```bash
# Share a public secret -> prints a Secret ID
bsec share --content "hello local chain" --to public --ttl 1h --max-reads 3

# View it back by ID (real eth_call + IPFS fetch)
bsec view <secret_id>

# List and revoke
bsec list
bsec revoke <secret_id>
```

> Shortcut: `./scripts/e2e-setup.sh` automates Steps 1–4 (bring up stack, deploy, configure,
> create + fund wallet), after which `BSEC_E2E=1 cargo test` runs the gated integration flows.

---

## 2. Deploying to Public Testnets

### Supported Networks & Faucets

| Network | Chain ID | `bsec` Network Flag | Free Token Faucets |
| :--- | :---: | :--- | :--- |
| **Polygon Amoy** | `80002` | `bsec config --network amoy` | • <https://faucet.polygon.technology/> |
| **Ethereum Sepolia** | `11155111` | `bsec config --network sepolia` | • <https://sepoliafaucet.com/><br>• <https://faucets.chain.link/> |
| **Base Sepolia** | `84532` | `bsec config --network base-sepolia` | • <https://faucets.chain.link/base-sepolia> |

---

### Deployment Commands by Network

Export your testnet wallet private key and RPC URL:

```bash
export PRIVATE_KEY="0x_your_private_key_here"
```

> On recent Foundry, add `--broadcast` to each `forge create` below to send the deploy
> transaction. After deploying, register the address and fund your `bsec` wallet:
>
> ```bash
> bsec config --network <net> --registry 0xYourDeployedRegistryAddress
> # then fund the `bsec wallet info` address from a faucet before share/view/revoke
> ```

#### A. Polygon Amoy Testnet (Chain ID 80002)

```bash
forge create contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url https://rpc-amoy.polygon.technology \
  --private-key $PRIVATE_KEY \
  --verify \
  --etherscan-api-key "YOUR_POLYGONSCAN_API_KEY"
```

#### B. Ethereum Sepolia Testnet (Chain ID 11155111)

```bash
forge create contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url https://rpc.sepolia.org \
  --private-key $PRIVATE_KEY \
  --verify \
  --etherscan-api-key "YOUR_ETHERSCAN_API_KEY"
```

#### C. Base Sepolia Testnet (Chain ID 84532)

```bash
forge create contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url https://sepolia.base.org \
  --private-key $PRIVATE_KEY \
  --verify \
  --etherscan-api-key "YOUR_BASESCAN_API_KEY"
```

---

## 3. Deploying to Production Mainnets

For production deployment to Polygon Mainnet (Chain ID `137`) or Base Mainnet (Chain ID `8453`):

### Security & Deployment Best Practices
1. **Use a Hardware Wallet or Keystore file**: Never expose plain-text mainnet private keys in shell history.
2. **Use Foundry Encrypted Keystore**:
   ```bash
   forge script ... --account my-mainnet-wallet --ask-vault-pass
   ```
3. **Verify Contract Source Code**: Ensure source code verification on Polygonscan/Basescan so users can audit the contract.

---

## 4. Contract Verification Quick Reference

If contract deployment succeeded but verification failed during `forge create`, verify retroactively:

```bash
forge verify-contract \
  <DEPLOYED_CONTRACT_ADDRESS> \
  contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --chain-id 80002 \
  --etherscan-api-key "YOUR_POLYGONSCAN_API_KEY"
```
