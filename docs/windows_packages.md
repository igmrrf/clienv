# Windows Package Managers Guide (Winget, Chocolatey, Scoop)

This guide covers distributing `bsec` across popular Windows package management systems: **Winget** (official Windows Package Manager), **Chocolatey**, and **Scoop**.

---

## 🪟 1. Windows Package Manager (`winget`)

Winget manifests are submitted to the official [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) GitHub repository.

### Step 1: Install `wingetcreate` CLI

```powershell
winget install Microsoft.WingetCreate
```

### Step 2: Generate Winget Manifest

```powershell
wingetcreate new https://github.com/igmrrf/bsec/releases/download/v0.1.0/bsec-windows-x86_64.zip
```

### Step 3: Sample Winget Manifest (`igmrrf.bsec.yaml`)

```yaml
PackageIdentifier: igmrrf.bsec
PackageVersion: 0.1.0
PackageName: bsec
Publisher: Francis Igbiriki
License: MIT
ShortDescription: Secure CLI tool to manage and encrypt environment variables
Installers:
  - Architecture: x64
    InstallerType: zip
    InstallerUrl: https://github.com/igmrrf/bsec/releases/download/v0.1.0/bsec-windows-x86_64.zip
    InstallerSha256: <CALCULATED_SHA256>
    NestedInstallerFiles:
      - RelativeFilePath: bsec.exe
ManifestType: singleton
ManifestVersion: 1.6.0
```

### User Installation Test:

```powershell
winget install igmrrf.bsec
```

---

## 🪟 2. Chocolatey (`choco`)

Chocolatey packages are built as `.nupkg` archives and pushed to [chocolatey.org](https://community.chocolatey.org/).

### Step 1: Create Package Specification (`bsec.nuspec`)

```xml
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>bsec</id>
    <version>0.1.0</version>
    <title>bsec CLI</title>
    <authors>Francis Igbiriki</authors>
    <projectUrl>https://github.com/igmrrf/bsec</projectUrl>
    <licenseUrl>https://github.com/igmrrf/bsec/blob/main/LICENSE</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>Secure CLI tool to manage and encrypt environment variables</description>
    <summary>bsec CLI env management tool</summary>
    <tags>cli env security encryption rust</tags>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
```

### Step 2: Package & Push

```powershell
choco pack
choco push bsec.0.1.0.nupkg --api-key <YOUR_CHOCO_API_KEY>
```

---

## 🪟 3. Scoop Manifest (`scoop`)

Scoop enables non-admin, portable Windows installations via custom buckets.

### Step 1: Create Scoop Bucket Repository

Create a GitHub repo named `scoop-bucket` containing `bucket/bsec.json`:

```json
{
    "version": "0.1.0",
    "description": "Secure CLI tool to manage and encrypt environment variables",
    "homepage": "https://github.com/igmrrf/bsec",
    "license": "MIT",
    "architecture": {
        "64bit": {
            "url": "https://github.com/igmrrf/bsec/releases/download/v0.1.0/bsec-windows-x86_64.zip",
            "hash": "<CALCULATED_SHA256>"
        }
    },
    "bin": "bsec.exe",
    "checkver": "github",
    "autoupdate": {
        "architecture": {
            "64bit": {
                "url": "https://github.com/igmrrf/bsec/releases/download/v$version/bsec-windows-x86_64.zip"
            }
        }
    }
}
```

### User Installation Test:

```powershell
scoop bucket add igmrrf https://github.com/igmrrf/scoop-bucket
scoop install bsec
```
