# GitHub Binary Releases & Cross-Compilation Guide

This guide details how to automatically compile and publish standalone, pre-built binary releases of `bsec` for **macOS**, **Linux**, and **Windows** using `cargo-dist` and GitHub Actions.

---

## 🌐 Supported Binary Targets

| Operating System | Architecture | Target Triple | Asset Format |
| :--- | :--- | :--- | :--- |
| **macOS** | Apple Silicon (M1/M2/M3/M4) | `aarch64-apple-darwin` | `.tar.gz` |
| **macOS** | Intel x86_64 | `x86_64-apple-darwin` | `.tar.gz` |
| **Linux** | x86_64 (GNU) | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| **Linux** | x86_64 (Static Musl) | `x86_64-unknown-linux-musl` | `.tar.gz` |
| **Windows** | x86_64 MSVC | `x86_64-pc-windows-msvc` | `.zip` / `.msi` |

---

## 🛠 Local Setup with `cargo-dist`

`cargo-dist` automates cross-compilation matrix builds and installer generation.

### Step 1: Install `cargo-dist`

```bash
cargo install cargo-dist
```

### Step 2: Initialize `cargo-dist` configuration

```bash
cargo dist init
```

This generates `dist` configurations inside [`Cargo.toml`](file:///Users/igmrrf/Desktop/tmp/bsec/Cargo.toml) and creates a GitHub Actions release workflow `.github/workflows/release.yml`.

---

## 🤖 GitHub Actions Workflow (`.github/workflows/release.yml`)

```yaml
name: Release Binaries

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    name: Build and Release Binaries
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact_name: bsec-linux-x86_64.tar.gz
          - os: macos-latest
            target: aarch64-apple-darwin
            artifact_name: bsec-macos-arm64.tar.gz
          - os: macos-13
            target: x86_64-apple-darwin
            artifact_name: bsec-macos-x86_64.tar.gz
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact_name: bsec-windows-x86_64.zip

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Build Release Binary
        run: cargo build --release --target ${{ matrix.target }}

      - name: Package Binaries (Unix)
        if: matrix.os != 'windows-latest'
        run: |
          tar -czvf ${{ matrix.artifact_name }} -C target/${{ matrix.target }}/release bsec

      - name: Package Binaries (Windows)
        if: matrix.os == 'windows-latest'
        run: |
          Compress-Archive -Path target/${{ matrix.target }}/release/bsec.exe -DestinationPath ${{ matrix.artifact_name }}

      - name: Upload to GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: ${{ matrix.artifact_name }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 🚀 Triggering a Release

To cut a new binary release:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

GitHub Actions will trigger, build binaries for all OS targets, and attach compiled archives to the GitHub Release page.
