
/Users/tldo/Desktop/tmp/vault/ts/
├── bin/                          # Binary executable files
│   └── clienv.js                 # Main CLI entry point
├── src/                          # Source code
│   ├── index.ts                  # Main entry point
│   ├── commands/                 # CLI commands
│   │   ├── init.ts               # Wallet initialization
│   │   ├── config.ts             # Configuration management
│   │   ├── share.ts              # Secret sharing
│   │   ├── view.ts               # Secret viewing
│   │   ├── list.ts               # List secrets
│   │   ├── revoke.ts             # Revoke access
│   │   └── wallet.ts             # Wallet management
│   ├── blockchain/               # Blockchain integration
│   │   ├── contracts/            # Smart contract interfaces
│   │   ├── networks.ts           # Network configurations
│   │   └── wallet.ts             # Wallet operations
│   ├── storage/                  # Storage mechanisms
│   │   ├── ipfs.ts               # IPFS integration
│   │   └── local.ts              # Local storage utilities
│   ├── crypto/                   # Cryptography utilities
│   │   ├── encryption.ts         # Encryption/decryption
│   │   ├── keys.ts               # Key management
│   │   └── signatures.ts         # Signature verification
│   ├── common/                   # Common utilities
│   │   ├── file.ts               # File operations
│   │   ├── validation.ts         # Input validation
│   │   └── logger.ts             # Logging utilities
│   ├── types/                    # TypeScript type definitions
│   │   ├── wallet.ts             # Wallet types
│   │   ├── config.ts             # Configuration types
│   │   └── secrets.ts            # Secret types
│   └── config/                   # Configuration templates
│       └── .env.development      # Development environment
├── dist/                         # Compiled JavaScript files
├── tests/                        # Test files
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   └── fixtures/                 # Test fixtures
├── docs/                         # Documentation
│   └── api.md                    # API documentation
├── examples/                     # Example usage
├── .env.dev                      # Development environment variables
├── package.json                  # Project metadata and dependencies
├── rollup.config.js              # Bundler configuration
├── .npmignore                    # Files to exclude from npm package
├── README.md                     # Project overview
├── PRD.md                        # Product Requirements Document
└── LICENSE.md                    # License information