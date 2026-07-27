# BSEC Deployment & Distribution Guides

This directory contains comprehensive, step-by-step deployment flows for distributing the **`bsec`** CLI application and deploying its smart contract infrastructure across multiple platforms, package managers, and environments.

---

## 📚 Guide Index

| Platform / Target | Description | Guide |
| :--- | :--- | :--- |
| **Cargo (crates.io)** | Publishing `bsec` as an open-source Rust crate | [`cargo.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/cargo.md) |
| **Homebrew** | Distributing `bsec` via Homebrew Formulae & Taps for macOS / Linux | [`homebrew.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/homebrew.md) |
| **GitHub Binary Releases** | Building standalone cross-platform binaries (macOS, Linux, Windows) with GitHub Actions & `cargo-dist` | [`binary_releases.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/binary_releases.md) |
| **Docker & Containers** | Containerizing `bsec` and publishing to Docker Hub & GHCR | [`docker.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/docker.md) |
| **Linux Package Managers** | Packaging for Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`), Arch (`AUR`), and `snap` | [`linux_packages.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/linux_packages.md) |
| **Windows Package Managers** | Packaging for Windows Package Manager (`winget`), Chocolatey, and Scoop | [`windows_packages.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/windows_packages.md) |
| **NPM Engine** | Wrapping Rust binary for execution via `npx bsec` / `npm install -g bsec` | [`npm.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/npm.md) |
| **Smart Contracts & EVM** | Deploying `BsecSecretRegistry.sol` to Anvil, Polygon, Base, Sepolia & IPFS | [`smart_contracts.md`](file:///Users/igmrrf/Desktop/tmp/bsec/docs/smart_contracts.md) |

---

## 🛠 Quick Overview of `bsec` Architecture

* **CLI Application**: Rust crate (`bsec`) built with `clap`, `tokio`, `k256`, `zeroize`, and `aes-gcm`.
* **Smart Contract**: Solidity contract (`contracts/BsecSecretRegistry.sol`) managed with Foundry.
* **Storage Layer**: IPFS integration (Local Kubo node / Pinata gateway).
