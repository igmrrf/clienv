# BSEC Smart Contract Deployment Guide

This document provides step-by-step instructions for compiling and deploying the **`BsecSecretRegistry`** smart contract across local testnets (Docker Anvil), EVM public testnets (Polygon Amoy, Ethereum Sepolia, Base Sepolia), and EVM production mainnets.

---

## 📋 Overview & Contract Architecture

The [`contracts/BsecSecretRegistry.sol`](contracts/BsecSecretRegistry.sol) contract manages access rules, expiration timestamps, read counters, IPFS CIDs, and verified sender identities (`msg.sender`) on-chain.

### Key Contract Functions

| Function | Access | Description |
| :--- | :--- | :--- |
| `shareSecret(...)` | External | Registers a new encrypted secret, its IPFS CID, expiration, and read limits on-chain. |
| `recordRead(bytes32 id)` | External | Increments read count after verifying authorization, expiration, and limits. |
| `revokeSecret(bytes32 id)` | Sender Only | Immediately revokes access to a secret. |
| `getSecretInfo(bytes32 id)` | View | Returns complete on-chain secret metadata and status. |

---

## 🛠️ Prerequisites & Setup

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

Anvil pre-funds 10 test accounts with 10,000 ETH each. Use Account 0 private key for local deployment:

```bash
forge create contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### Output Example:

```text
Deployer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
Transaction hash: 0x3e18a...
```

### Step 3: Register Deployed Address in `bsec`

Save the deployed contract address in your network configuration:

```bash
bsec config --network local --rpc "http://localhost:8545"
```

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
