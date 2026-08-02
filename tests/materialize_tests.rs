//! Secret → File Materialization Integration Tests
//!
//! Target Modules: `src/materialize.rs`, `src/secrets.rs`, `src/main.rs`
//! Flow Tested:
//!   - `bsec share --file <f> --as <kind>` -> `bsec materialize <id> --dir <d>` (bytes + 0600)
//!   - `bsec share --bundle <manifest>` -> `bsec materialize <id> --dir <d>` (all members)
//!   - `bsec run --secret <id> -- <cmd>` stages files and wipes the temp dir on exit
//!   - `bsec materialize <id> --as schema` discloses key names but not values
//!   - `--no-export` seals a secret against file materialization (terminal view still works)
//!
//! Like the other on-chain flows these need a deployed registry, a funded wallet, and an IPFS
//! backend, so they are skipped unless `BSEC_E2E=1`. Provision with `scripts/e2e-setup.sh` and
//! run with `--test-threads=1`.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::path::Path;
use std::process::Command;

fn e2e_enabled() -> bool {
    std::env::var("BSEC_E2E").map(|v| v == "1").unwrap_or(false)
}

macro_rules! require_e2e {
    () => {
        if !e2e_enabled() {
            eprintln!(
                "SKIP: on-chain e2e. Use scripts/e2e-setup.sh to provision anvil + IPFS + a funded \
                 wallet, then set BSEC_E2E=1 (run with --test-threads=1)."
            );
            return Ok(());
        }
    };
}

fn bsec(home: &Path) -> Result<Command, Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("bsec")?;
    cmd.current_dir(home);
    cmd.env("BSEC_HOME", home);
    Ok(cmd)
}

fn init_wallet(home: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = bsec(home)?;
    cmd.arg("init").arg("--overwrite");
    cmd.assert().success();
    Ok(())
}

/// Parse `Secret ID: <id>` out of a `share` command's stdout.
fn extract_secret_id(stdout: &str) -> String {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Secret ID: ") {
            return rest.trim().to_string();
        }
    }
    String::new()
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// share `--file cert.pem --as pem` -> materialize to `--dir` -> bytes identical, mode 0600.
#[test]
fn test_materialize_single_pem_bytes_and_mode() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
    let dir = assert_fs::TempDir::new()?;
    init_wallet(dir.path())?;

    let pem_body = "-----BEGIN CERTIFICATE-----\nMIIBhTNTESTBYTES\n-----END CERTIFICATE-----\n";
    let src = dir.path().join("cert.pem");
    std::fs::write(&src, pem_body)?;

    let mut share = bsec(dir.path())?;
    share.args(["share", "--file"]).arg(&src);
    share.args(["--as", "pem", "--to", "public", "--ttl", "1h"]);
    let out = share.assert().success();
    let id = extract_secret_id(&String::from_utf8(out.get_output().stdout.clone())?);
    assert!(!id.is_empty());

    let out_dir = dir.path().join("materialized");
    let mut mat = bsec(dir.path())?;
    mat.arg("materialize").arg(&id).arg("--dir").arg(&out_dir);
    mat.assert()
        .success()
        .stdout(predicate::str::contains("mode 0600"));

    let written = out_dir.join("cert.pem");
    assert_eq!(std::fs::read_to_string(&written)?, pem_body);
    #[cfg(unix)]
    assert_eq!(mode_of(&written), 0o600);
    Ok(())
}

/// share `--bundle` (pem + json + env) -> materialize all three -> files present;
/// then `run --secret <id>` sees the staged file via its `$CERT_FILE` path.
#[test]
fn test_bundle_materialize_and_run_staging() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
    let dir = assert_fs::TempDir::new()?;
    init_wallet(dir.path())?;

    std::fs::write(dir.path().join("cert.pem"), "PEMBODY")?;
    std::fs::write(dir.path().join("creds.json"), r#"{"k":1}"#)?;
    std::fs::write(dir.path().join(".env.prod"), "DB=postgres\nPORT=5432")?;
    let manifest = dir.path().join("bundle.json");
    std::fs::write(
        &manifest,
        r#"{"members":[
            {"path":"cert.pem","as":"pem","filename":"cert.pem"},
            {"path":"creds.json","as":"json","filename":"creds.json"},
            {"path":".env.prod","as":"env","filename":".env"}
        ]}"#,
    )?;

    let mut share = bsec(dir.path())?;
    share.arg("share").arg("--bundle").arg(&manifest);
    share.args(["--to", "public", "--ttl", "1h"]);
    let out = share.assert().success();
    let id = extract_secret_id(&String::from_utf8(out.get_output().stdout.clone())?);
    assert!(!id.is_empty());

    // Materialize the whole bundle.
    let out_dir = dir.path().join("secrets");
    let mut mat = bsec(dir.path())?;
    mat.arg("materialize").arg(&id).arg("--dir").arg(&out_dir);
    mat.assert().success();
    assert_eq!(std::fs::read_to_string(out_dir.join("cert.pem"))?, "PEMBODY");
    assert!(out_dir.join("creds.json").exists());
    assert!(out_dir.join(".env").exists());

    // run --secret stages files; the child asserts $CERT_FILE exists and env member injected.
    let mut run = bsec(dir.path())?;
    run.arg("run").arg("--secret").arg(&id);
    run.arg("--").arg("sh").arg("-c").arg("test -f \"$CERT_FILE\" && test \"$DB\" = postgres");
    run.assert().success();
    Ok(())
}

/// `run --secret` leaves no staged temp dir after exit: the child records its staged path in a
/// sidecar file, and after the run that path must no longer exist.
#[test]
fn test_run_secret_wipes_temp_dir() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
    let dir = assert_fs::TempDir::new()?;
    init_wallet(dir.path())?;

    std::fs::write(dir.path().join("cert.pem"), "PEMBODY")?;
    let manifest = dir.path().join("bundle.json");
    std::fs::write(&manifest, r#"{"members":[{"path":"cert.pem","as":"pem","filename":"cert.pem"}]}"#)?;

    let mut share = bsec(dir.path())?;
    share.arg("share").arg("--bundle").arg(&manifest);
    share.args(["--to", "public", "--ttl", "1h"]);
    let out = share.assert().success();
    let id = extract_secret_id(&String::from_utf8(out.get_output().stdout.clone())?);

    let sidecar = dir.path().join("staged_path.txt");
    let mut run = bsec(dir.path())?;
    run.arg("run").arg("--secret").arg(&id);
    run.arg("--")
        .arg("sh")
        .arg("-c")
        .arg(format!("printf '%s' \"$CERT_FILE\" > {}", sidecar.display()));
    run.assert().success();

    let staged_path = std::fs::read_to_string(&sidecar)?;
    assert!(!staged_path.is_empty());
    // The staged file (and its temp dir) must be gone now that the child has exited.
    assert!(!Path::new(&staged_path).exists(), "staged file should be wiped: {}", staged_path);
    Ok(())
}

/// `materialize --as schema` yields sorted key names with no values.
#[test]
fn test_materialize_schema_keys_only() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
    let dir = assert_fs::TempDir::new()?;
    init_wallet(dir.path())?;

    let src = dir.path().join(".env.prod");
    std::fs::write(&src, "DB_URL=postgres://secretvalue\nAPI_KEY=supersecret")?;
    let mut share = bsec(dir.path())?;
    share.arg("share").arg("--file").arg(&src);
    share.args(["--as", "env", "--to", "public", "--ttl", "1h"]);
    let out = share.assert().success();
    let id = extract_secret_id(&String::from_utf8(out.get_output().stdout.clone())?);

    let schema = dir.path().join(".env.schema");
    let mut mat = bsec(dir.path())?;
    mat.arg("materialize").arg(&id).args(["--as", "schema", "--file"]).arg(&schema);
    mat.assert().success();

    let text = std::fs::read_to_string(&schema)?;
    assert!(text.contains("API_KEY="));
    assert!(text.contains("DB_URL="));
    assert!(!text.contains("secretvalue"));
    assert!(!text.contains("supersecret"));
    Ok(())
}

/// `--no-export` blocks file materialization but leaves terminal `view` working.
#[test]
fn test_no_export_blocks_materialize_allows_view() -> Result<(), Box<dyn std::error::Error>> {
    require_e2e!();
    let dir = assert_fs::TempDir::new()?;
    init_wallet(dir.path())?;

    let src = dir.path().join("secret.cred");
    std::fs::write(&src, "TOP_SECRET_TOKEN")?;
    let mut share = bsec(dir.path())?;
    share.arg("share").arg("--file").arg(&src).arg("--no-export");
    share.args(["--to", "public", "--ttl", "1h"]);
    let out = share.assert().success();
    let id = extract_secret_id(&String::from_utf8(out.get_output().stdout.clone())?);

    // materialize refused
    let mut mat = bsec(dir.path())?;
    mat.arg("materialize").arg(&id).arg("--dir").arg(dir.path().join("out"));
    mat.assert().failure().stderr(predicate::str::contains("no-export"));

    // terminal view still works
    let mut view = bsec(dir.path())?;
    view.arg("view").arg(&id);
    view.assert().success().stdout(predicate::str::contains("TOP_SECRET_TOKEN"));
    Ok(())
}
