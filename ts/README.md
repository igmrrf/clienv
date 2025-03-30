# CLIENV

A powerful CLI tool for secure, decentralized environment variable management and secret sharing that leverages blockchain technology for authentication and storage.

## Features

- 🔄 Convert between different environment file formats (JSON, YAML, .env)
- 🔒 Blockchain-based secure secret sharing
- ✅ Validate environment variables against schemas
- 📝 Generate environment templates and schemas
- 🔐 End-to-end encryption (.env files)
- 📋 Log and display environment values
- 🔗 Git integration for automatic encryption
- 👥 Wallet-based authentication
- 👥 User specific secret sharing
- ⛓️ Smart contract-based access control
- 🕒 Time-based auto-destruction
- 📊 Read count tracking
- 💾 IPFS decentralized storage

## Installation

```bash
# Using npm
npm install -g clienv

# Using yarn
yarn global add clienv

# Using brew
brew install clienv
```

## Core Components

### 1. Wallet Management

Initialize and manage your blockchain wallet:

```bash
# Initialize wallet
clienv init

# Import existing wallet
clienv init --import-mnemonic

# Configure network
clienv config --network polygon

# View wallet info
clienv wallet info
```

### 2. Secret Sharing

Share secrets with blockchain-based authentication:

```bash
# Share a secret with 1-hour expiration
clienv share "secret text"

# Share from file 
clienv share --file secret.txt

# Share a secret with 1-hour expiration
clienv share --content "secret text" --ttl 1h --to 0x123...

# Share from file with read limit
clienv share --file secret.txt --ttl 7d --max-reads 5

# View a secret
clienv view <secret-id>

# Save to file
clienv view <secret-id> --output decrypted.txt

# List active secrets
clienv list

# Revoke access
clienv revoke <secret-id>
```

User-specific secret sharing:

```bash
# Share secret with specific user
clienv share "secret-api-key" -t 1h -l 1 -u <user-id>
```

Where `<user-id>` can be any unique identifier (e.g., wallet-address)

### 3. Environment File Management

Convert between formats:

```bash
# Convert JSON to .env
clienv convert --file=config.json --out=.env.local

# Convert with prefix
clienv convert --file=config.json --prefix="NEXT_PUBLIC_"

# Embedded JavaScript output
clienv convert --file=.env.local --out=config.js --embed
```

Advanced conversion examples:

```bash
# Export environment variables
clienv convert config.json --prefix="export "

# Vue.js environment variables
clienv convert config.json --prefix="VUE_APP_"

# Next.js public variables
clienv convert config.json --prefix="NEXT_PUBLIC_"

# Embedded JavaScript output
clienv convert .env.local --out=config.js --embed
```

### 4. Environment Validation

Basic validation:

```bash
# Validate against schema
clienv validate -s .env.schema -e .env.local
```

CI/CD Integration:

```json
{
  "scripts": {
    "check-env": "clienv check -s .env.schema -e .env.local",
    "dev": "npm run check-env && next dev"
  }
}
```

The validation will:

- Ensure all required variables are present
- Check for variables in .env that aren't in schema
- Verify schema compliance before deployment

### Template Generation

Generate .env templates from existing files:

```bash
# Generate template from .env
clienv template --env .env

# Result (.env.template):
API_KEY=#Your API_KEY here
DATABASE_URL=#Your DATABASE_URL here
```

### 5. File Encryption

Basic encryption:

```bash
# Set encryption key
echo "your_password_here" >> .env.pass

# Encrypt
clienv encrypt .env -o .env.enc

# Decrypt
clienv decrypt .env.enc -o .env
```

Multiple environment support:

```bash
# Production environment
echo "prod-password" >> .env.prod.pass
clienv encrypt .env.prod 

clienv decrypt .env.prod.enc # Looks for $DOTENV_PROD_PASS or .env.prod.pass

# Development environment
echo "dev-password" >> .env.dev.pass
clienv encrypt .env.dev

clienv decrypt .env.dev.enc # Looks for $DOTENV_DEV_PASS or .env.dev.pass

# custom suffix
senv decrypt .env.prod.suffix # Looks for $DOTENV_PROD_SUFFIX_PASS or .env.prod.suffix.pass
```

Password configuration:

```bash
# Global encryption key (~/.bash_profile, ~/.zshrc)
export DOTENV_PASS=your_password_here

# Directory encryption key
echo "your_password_here" >> .env.pass
```

#### Git Integration

Set up automatic encryption of .env files before commits:

```bash
# Add pre-commit hook
echo "#!/bin/sh" >> .git/hooks/pre-commit
echo "clienv encrypt .env -o .env.enc" >> .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Logging

```bash
# View specific environment variable
clienv log MONGO_URL --file=".env.local"

# Output to echo
clienv log --log=MONGO_URL --file=".env.local" --out=echo
```

### Environment Variables

- `DOTENV_PASS`: Global encryption password
- Individual file passwords: `DOTENV_<ENV>_PASS` (e.g., `DOTENV_PROD_PASS`)
- Password files: `.env.pass` or `.env.<environment>.pass`

Environment variables take precedence over password files:

- `DOTENV_PROD_PASS` overrides `.env.prod.pass`
- `DOTENV_DEV_PASS` overrides `.env.dev.pass`

## Technical Architecture

### Blockchain Components

- Network: Ethereum/Polygon/Other EVM
- Smart Contracts: Solidity
- Storage: IPFS for encrypted content
- Gas optimization for operations

### Security Features

- End-to-end encryption
- Zero-knowledge storage
- Automatic content destruction
- Access control via smart contract
- Chain-specific signature verification
- Gas limit protection
- IPFS content verification

### Local Storage Structure

```typescript
interface LocalConfig {
  walletData: EncryptedWallet;
  networkConfig: {
    chainId: number;
    rpcUrl: string;
    contractAddress: string;
  };
  ipfsConfig: {
    gateway: string;
    pinningService?: string;
  };
}
```

## Configuration

### Environment Variables

- `DOTENV_PASS`: Global encryption password
- Individual file passwords: `DOTENV_<ENV>_PASS`
- Password files: `.env.pass` or `.env.<environment>.pass`

### Wallet Configuration

- Private/public key pair
- Encrypted wallet storage
- Mnemonic phrase backup
- Optional password protection

## CLI Options Reference

```bash
Commands:
  # Wallet Management
  init         Initialize or import wallet
  wallet       Manage wallet settings
  config       Configure network settings
  
  # Secret Management
  share        Share secrets securely
    --ttl, -t      Time-to-live (e.g. 1m, 2h, 1d)
    --limit, -t   Number of times the secret can be read
    --to, --user, -u       Recipient wallet address
    --content  Secret content
    --file, -f     Path to a text file containing the secret
    --max-reads, -m  Maximum number of reads

  view         View shared secrets
    --id       Secret ID
    --output, -o  Output file path
  hide         Hide a secret
    --id       Secret ID
    --all      Hide all secrets
    --user, -u   Hide secrets shared with a specific user
    --all-users, -a  Hide secrets shared with all users
  list         List active secrets
    --user, -u   List secrets shared with a specific user
    --all-users, -a  List secrets shared with all users
    --all      List all secrets
    --expired    List expired secrets
    --active     List active secrets
    
  revoke       Revoke secret access
  
  # Environment Management
  convert      Convert between environment file formats
  validate     Validate environment files against schema
  generate     Generate schema from environment files
  template     Generate environment templates
  encrypt      Encrypt environment files
  decrypt      Decrypt environment files
  log          Display environment variables

Global Options:
  --network    Specify blockchain network
  --gas-limit  Set maximum gas limit
  --out        Output file path
  --prefix     Environment variable prefix
  --file       Input file path
  --embed     Embed as JavaScript variables
  --suffix    Environment variable suffix

```

## Security Architecture

### Wallet Security

- Encrypted private key storage
- Optional hardware wallet support
- Mnemonic backup
- Session-based unlock

### Content Security

- End-to-end encryption
- Zero-knowledge storage
- Automatic content destruction
- Smart contract-based access control

### Network Security

- Chain-specific signature verification
- Gas limit protection
- RPC endpoint validation
- IPFS content verification

## Future Roadmap

### Phase 1

- Multi-signature secret sharing
- Threshold encryption support
- Custom token-gated access
- Automated backup solutions

### Phase 2

- Cross-chain support
- Layer 2 optimization
- DAO integration
- Secret recovery mechanisms

### Phase 3

- Web3 identity integration
- Zero-knowledge proofs
- Compliance features
- Enterprise key management

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE.md) [©igmrrf](https://github.com/igmrrf)
