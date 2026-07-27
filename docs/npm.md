# NPM Wrapper & NPX Execution Guide (`npm` / `npx`)

This guide details how to wrap the Rust `bsec` binary into an npm package, enabling JavaScript / TypeScript developers to install it via `npm install -g bsec` or execute it directly without compilation via `npx bsec`.

---

## 🏗 Architecture of binary NPM wrappers

1. The root `npm` package (`bsec`) acts as a wrapper script (`bin/bsec.js`).
2. Optional platform-specific binary packages (`@bsec/cli-darwin-arm64`, `@bsec/cli-linux-x64`, etc.) contain platform-native binaries compiled from Rust.
3. When `npx bsec` is invoked, the wrapper detects host OS/architecture and delegates execution to the native binary.

---

## 📁 Package Directory Layout

```text
npm-package/
├── bin/
│   └── bsec.js
├── index.js
├── package.json
└── README.md
```

---

## 🛠 Step 1: `package.json`

```json
{
  "name": "bsec-cli",
  "version": "0.1.0",
  "description": "Secure CLI tool to manage and encrypt environment variables",
  "bin": {
    "bsec": "./bin/bsec.js"
  },
  "scripts": {
    "postinstall": "node ./scripts/install-binary.js"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/igmrrf/bsec.git"
  },
  "keywords": [
    "cli",
    "env",
    "environment-variables",
    "encryption",
    "secrets"
  ],
  "author": "Francis Igbiriki <francis.igbiriki@gmail.com>",
  "license": "MIT"
}
```

---

## 🛠 Step 2: Binary Launcher (`bin/bsec.js`)

```javascript
#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const platform = process.platform;
const arch = process.arch;

const binaryName = platform === 'win32' ? 'bsec.exe' : 'bsec';
const binaryPath = path.join(__dirname, '..', 'binaries', `${platform}-${arch}`, binaryName);

if (!fs.existsSync(binaryPath)) {
  console.error(`Error: Prebuilt binary for ${platform}-${arch} not found at ${binaryPath}`);
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), { stdio: 'inherit' });

child.on('exit', (code) => {
  process.exit(code || 0);
});
```

---

## 🚀 Publishing to NPM Registry

### Step 1: Login to NPM

```bash
npm login
```

### Step 2: Publish Package

```bash
npm publish --access public
```

---

## 🧪 User Execution

Users can execute `bsec` instantly without needing Rust toolchains:

```bash
# Direct zero-install execution
npx bsec-cli --help

# Global installation
npm install -g bsec-cli
bsec --version
```
