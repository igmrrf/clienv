# Cargo (crates.io) Deployment Guide

This guide details how to publish `bsec` to [crates.io](https://crates.io), allowing users to install the CLI directly using `cargo install bsec`.

---

## 📋 Prerequisites

1. An active account on [crates.io](https://crates.io).
2. API Token generated under **Account Settings -> API Tokens** on crates.io.
3. Verified email address on crates.io.

---

## 🛠 Step-by-Step Publishing Flow

### Step 1: Login to Crates.io via Cargo

Run the login command and paste your crates.io API token:

```bash
cargo login <YOUR_CRATES_IO_API_TOKEN>
```

---

### Step 2: Validate Manifest & Workspace

Ensure [`Cargo.toml`](file:///Users/igmrrf/Desktop/tmp/bsec/Cargo.toml) contains all required fields:

```toml
[package]
name = "bsec"
version = "0.1.0"
authors = ["The Lazy <francis.igbiriki@gmail.com>"]
license = "MIT OR Apache-2.0"
description = "A secure CLI tool to manage and encrypt environment variables"
readme = "README.md"
homepage = "https://bsec.dev"
repository = "https://github.com/igmrrf/bsec"
keywords = ["cli", "env", "manage", "track", "encrypt"]
categories = ["command-line-utilities", "security"]
edition = "2024"
```

---

### Step 3: Dry-Run Packaging & Check

Perform a publish dry-run to verify that all included files package cleanly without warnings or errors:

```bash
cargo publish --dry-run
```

Verify included files list:
```bash
cargo package --list
```

---

### Step 4: Publish to Crates.io

Publish the crate to crates.io:

```bash
cargo publish
```

---

## 🔄 Automated CI/CD Publishing (GitHub Actions)

Add `.github/workflows/publish-cargo.yml`:

```yaml
name: Publish to Crates.io

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Cargo Publish
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        run: cargo publish
```

---

## 🧪 Installation Verification

Once published, users can install `bsec` globally:

```bash
cargo install bsec
bsec --version
```
