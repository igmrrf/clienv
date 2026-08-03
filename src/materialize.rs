use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use crate::secrets::{BundleMember, IpfsPayload, SecretKind};

/// Output format for `materialize` / `view --file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Env,
    Pem,
    Json,
    Cred,
    Schema,
}

/// Reject anything that is not a safe plain basename. Sender-supplied filenames are
/// attacker-influenced, so any path separator, traversal token, home expansion, absolute
/// path, or NUL is refused. Returns the validated basename on success.
pub fn sanitize_basename(name: &str) -> Result<String> {
    let reject = |why: &str| Err(anyhow!("unsafe filename {:?}: {}", name, why));
    if name.is_empty() {
        return reject("empty");
    }
    if name.contains('\0') {
        return reject("contains NUL");
    }
    if name.contains('/') || name.contains('\\') {
        return reject("contains a path separator");
    }
    if name.contains("..") {
        return reject("contains a traversal token");
    }
    if name.starts_with('~') {
        return reject("starts with a home expansion");
    }
    if name == "." {
        return reject("refers to the current directory");
    }
    // Cross-check against the platform's own notion of a filename: the parsed path must
    // consist of exactly one normal component equal to the input.
    let path = std::path::Path::new(name);
    let mut comps = path.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == name => Ok(name.to_string()),
        _ => reject("is not a plain basename"),
    }
}

/// Decode a payload member/body to raw bytes per its encoding ("utf8" | "base64").
pub fn decode_body(content: &str, encoding: &str) -> Result<Vec<u8>> {
    use base64::prelude::*;
    match encoding {
        "utf8" => Ok(content.as_bytes().to_vec()),
        "base64" => BASE64_STANDARD
            .decode(content)
            .map_err(|e| anyhow!("invalid base64 member body: {}", e)),
        other => Err(anyhow!("unknown content encoding {:?}", other)),
    }
}

impl SecretKind {
    fn as_format(self) -> OutputFormat {
        match self {
            SecretKind::Env => OutputFormat::Env,
            SecretKind::Pem => OutputFormat::Pem,
            SecretKind::Json => OutputFormat::Json,
            SecretKind::Cred => OutputFormat::Cred,
        }
    }
}

/// Parse an `--as` string into an OutputFormat.
pub fn parse_format(s: &str) -> Result<OutputFormat> {
    match s.to_lowercase().as_str() {
        "env" => Ok(OutputFormat::Env),
        "pem" => Ok(OutputFormat::Pem),
        "json" => Ok(OutputFormat::Json),
        "cred" => Ok(OutputFormat::Cred),
        "schema" => Ok(OutputFormat::Schema),
        other => Err(anyhow!("unknown format {:?} (use env|pem|json|cred|schema)", other)),
    }
}

/// Best-effort content sniff for untagged legacy secrets.
fn sniff_format(content: &str) -> OutputFormat {
    let trimmed = content.trim_start();
    if trimmed.starts_with("-----BEGIN") {
        return OutputFormat::Pem;
    }
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(content).is_ok()
    {
        return OutputFormat::Json;
    }
    // KEY=VAL lines => env. Require at least one non-comment line with an '='.
    let looks_env = content.lines().any(|l| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#') && t.contains('=')
    });
    if looks_env {
        OutputFormat::Env
    } else {
        OutputFormat::Cred
    }
}

/// Resolve the output format for a single (non-bundle) secret.
/// Order: explicit `--as` > payload.kind > content sniff. `content` is the decrypted body.
pub fn resolve_format(explicit: Option<OutputFormat>, kind: Option<SecretKind>, content: &str) -> OutputFormat {
    if let Some(f) = explicit {
        return f;
    }
    if let Some(k) = kind {
        return k.as_format();
    }
    sniff_format(content)
}

/// Extract a keys-only schema (sorted `KEY=` lines, no values) from a keyed secret body.
/// Errors for pem/opaque content that has no key set.
pub fn extract_schema_from(content: &str, fmt: OutputFormat) -> Result<String> {
    let keys: Vec<String> = match fmt {
        OutputFormat::Json => {
            let val: serde_json::Value = serde_json::from_str(content)
                .map_err(|_| anyhow!("secret is not valid JSON; no schema to extract"))?;
            match val {
                serde_json::Value::Object(map) => map.keys().cloned().collect(),
                _ => return Err(anyhow!("JSON secret is not an object; no schema to extract")),
            }
        }
        OutputFormat::Env | OutputFormat::Cred => {
            let map = crate::env_file::parse_env_content(content);
            if map.is_empty() {
                return Err(anyhow!("secret has no KEY=VALUE pairs; no schema to extract"));
            }
            map.keys().cloned().collect()
        }
        OutputFormat::Pem => {
            return Err(anyhow!("secret is kind=pem; no schema to extract"));
        }
        OutputFormat::Schema => {
            return Err(anyhow!("cannot extract a schema of a schema"));
        }
    };
    let mut keys = keys;
    keys.sort();
    keys.dedup();
    let mut out: String = keys.iter().map(|k| format!("{}=", k)).collect::<Vec<_>>().join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

/// Emit keys-only schema text for a single decrypted secret payload. Honors no_export.
pub fn extract_schema(payload: &IpfsPayload) -> Result<String> {
    if payload.no_export {
        return Err(anyhow!("sender sealed this secret (--no-export); terminal view only"));
    }
    let encoding = payload.content_encoding.as_deref().unwrap_or("utf8");
    if encoding != "utf8" {
        return Err(anyhow!("secret body is binary; no schema to extract"));
    }
    let fmt = resolve_format(None, payload.kind, &payload.content);
    extract_schema_from(&payload.content, fmt)
}

/// Where to write a single materialized secret.
pub enum OutTarget {
    /// Explicit output file path (parent dir created 0700 if needed).
    File(PathBuf),
    /// Output directory; the basename comes from payload.filename or a per-kind default.
    Dir(PathBuf),
}

/// Default output basename for a format when the sender supplied none.
fn default_filename(fmt: OutputFormat) -> &'static str {
    match fmt {
        OutputFormat::Env => ".env",
        OutputFormat::Pem => "cert.pem",
        OutputFormat::Json => "secret.json",
        OutputFormat::Cred => "credential",
        OutputFormat::Schema => ".env.schema",
    }
}

/// Create `dir` (and parents) with 0700 permissions on unix.
fn ensure_dir_0700(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    // Create born-secure: DirBuilder with recursive+mode applies 0700 to each component it
    // creates, so an intermediate dir is never briefly world-traversable at the process umask
    // before a follow-up chmod (as create_dir_all + set_permissions on the leaf would leave it).
    // Pre-existing components are left untouched, which is the desired behavior.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Write `bytes` to `path` at mode 0600, refusing to clobber unless `force`.
fn write_guarded(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir_0700(parent)?;
    }
    if force {
        crate::wallet::write_secure_file(path, bytes)?;
    } else {
        // Exclusive create (O_EXCL): the "do not overwrite" decision is atomic, closing the
        // TOCTOU window a prior `path.exists()` check would open. An AlreadyExists error — whether
        // the file was there all along or an attacker interposed one between calls — maps back to
        // the user-facing "use --force" message.
        crate::wallet::write_secure_file_new(path, bytes).map_err(|e| {
            if let Some(io) = e.downcast_ref::<std::io::Error>()
                && io.kind() == std::io::ErrorKind::AlreadyExists
            {
                return anyhow!("refusing to overwrite {} (use --force)", path.display());
            }
            e
        })?;
    }
    Ok(())
}

/// Materialize a single decrypted secret to a path/dir. Enforces no_export, 0600, overwrite guard.
/// `fmt` is the already-resolved output format (may be Schema).
pub fn materialize_single(
    payload: &IpfsPayload,
    fmt: OutputFormat,
    out: OutTarget,
    force: bool,
) -> Result<PathBuf> {
    if payload.no_export {
        return Err(anyhow!("sender sealed this secret (--no-export); terminal view only"));
    }
    if payload.members.is_some() {
        return Err(anyhow!("secret is a bundle; use --dir to materialize all members"));
    }

    let bytes: Vec<u8> = if fmt == OutputFormat::Schema {
        // extract_schema re-checks no_export/binary and resolves the keyed format.
        extract_schema(payload)?.into_bytes()
    } else {
        let encoding = payload.content_encoding.as_deref().unwrap_or("utf8");
        if fmt == OutputFormat::Env && encoding != "utf8" {
            return Err(anyhow!("env output requires utf8 content, but body is {}", encoding));
        }
        decode_body(&payload.content, encoding)?
    };

    let path = match out {
        OutTarget::File(p) => p,
        OutTarget::Dir(dir) => {
            let name = match payload.filename.as_deref() {
                Some(f) => sanitize_basename(f)?,
                None => default_filename(fmt).to_string(),
            };
            dir.join(name)
        }
    };

    write_guarded(&path, &bytes, force)?;
    Ok(path)
}

/// Decode a bundle member's body to raw bytes, sanitizing its filename.
fn member_bytes(m: &BundleMember) -> Result<Vec<u8>> {
    decode_body(&m.content, &m.encoding)
}

/// Materialize a bundle's members into `dir` (created 0700). Returns written paths.
/// Enforces no_export, filename sanitization, 0600, and the overwrite guard per member.
pub fn materialize_bundle(payload: &IpfsPayload, dir: &Path, force: bool) -> Result<Vec<PathBuf>> {
    if payload.no_export {
        return Err(anyhow!("sender sealed this secret (--no-export); terminal view only"));
    }
    let members = payload
        .members
        .as_ref()
        .ok_or_else(|| anyhow!("secret is not a bundle; use single-file materialization"))?;

    ensure_dir_0700(dir)?;

    let mut written = Vec::with_capacity(members.len());
    for m in members {
        let name = sanitize_basename(&m.filename)?;
        let path = dir.join(name);
        let bytes = member_bytes(m)?;
        write_guarded(&path, &bytes, force)?;
        written.push(path);
    }
    Ok(written)
}

/// Infer a SecretKind from a path's extension (spec §6.2). Unknown => Cred.
pub fn infer_kind(path: &Path) -> SecretKind {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    // `.env`, `.env.prod`, etc. have file_name starting with ".env" but Path::extension
    // treats ".env" as having no extension, so check the name too.
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == ".env" || name.starts_with(".env.") || ext == "env" {
        return SecretKind::Env;
    }
    match ext.as_str() {
        "pem" | "crt" | "key" => SecretKind::Pem,
        "json" => SecretKind::Json,
        _ => SecretKind::Cred,
    }
}

/// Read a file into a (body, encoding) pair. UTF-8 files are stored verbatim ("utf8");
/// binary files are base64-encoded ("base64").
pub fn read_file_body(path: &Path) -> Result<(String, String)> {
    let bytes = std::fs::read(path).map_err(|e| anyhow!("reading {}: {}", path.display(), e))?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok((s, "utf8".to_string())),
        Err(e) => {
            use base64::prelude::*;
            Ok((BASE64_STANDARD.encode(e.as_bytes()), "base64".to_string()))
        }
    }
}

#[derive(serde::Deserialize)]
struct ManifestMember {
    path: String,
    #[serde(rename = "as")]
    as_kind: Option<String>,
    filename: Option<String>,
    env: Option<String>,
}

#[derive(serde::Deserialize)]
struct BundleManifest {
    members: Vec<ManifestMember>,
}

/// Parse a kind string (env|pem|json|cred) into a SecretKind.
pub fn parse_kind(s: &str) -> Result<SecretKind> {
    match s.to_lowercase().as_str() {
        "env" => Ok(SecretKind::Env),
        "pem" => Ok(SecretKind::Pem),
        "json" => Ok(SecretKind::Json),
        "cred" => Ok(SecretKind::Cred),
        other => Err(anyhow!("unknown kind {:?} (use env|pem|json|cred)", other)),
    }
}

/// Load a bundle manifest and read each listed file into a (plaintext) BundleMember.
/// Filenames are sanitized to plain basenames. Paths are resolved relative to the manifest's
/// own directory so a manifest is portable.
pub fn load_bundle_members(manifest_path: &Path) -> Result<Vec<BundleMember>> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| anyhow!("reading manifest {}: {}", manifest_path.display(), e))?;
    let manifest: BundleManifest =
        serde_json::from_str(&text).map_err(|e| anyhow!("invalid bundle manifest: {}", e))?;
    if manifest.members.is_empty() {
        return Err(anyhow!("bundle manifest has no members"));
    }
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    let mut members = Vec::with_capacity(manifest.members.len());
    for m in manifest.members {
        let raw_path = Path::new(&m.path);
        let file_path = if raw_path.is_absolute() {
            raw_path.to_path_buf()
        } else {
            base.join(raw_path)
        };
        let kind = match m.as_kind {
            Some(ref k) => parse_kind(k)?,
            None => infer_kind(&file_path),
        };
        let filename = match m.filename {
            Some(f) => sanitize_basename(&f)?,
            None => {
                let base = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow!("member {:?} has no filename", m.path))?;
                sanitize_basename(base)?
            }
        };
        let (content, encoding) = read_file_body(&file_path)?;
        members.push(BundleMember { kind, filename, content, encoding, env: m.env });
    }
    Ok(members)
}

/// Derive the injected env var name for a staged file: uppercased filename stem with
/// leading dots stripped and non-alphanumerics folded to `_`, suffixed `_FILE`.
/// e.g. "service-account.json" -> "SERVICE_ACCOUNT_FILE"; ".env" -> "ENV_FILE".
pub fn stem_env_key(filename: &str) -> String {
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let cleaned: String = stem
        .trim_start_matches('.')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    let cleaned = cleaned.trim_matches('_');
    format!("{}_FILE", if cleaned.is_empty() { "SECRET" } else { cleaned })
}

fn is_file_kind(kind: SecretKind) -> bool {
    matches!(kind, SecretKind::Pem | SecretKind::Json | SecretKind::Cred)
}

/// RAII temp dir (0700) that wipes itself on Drop; used by `run --secret` staging.
pub struct StagedDir {
    path: PathBuf,
}

impl StagedDir {
    /// Create a fresh `<os-temp>/bsec-<random-hex>/` dir at mode 0700.
    pub fn new() -> Result<Self> {
        use aes_gcm::aead::rand_core::RngCore;
        use aes_gcm::aead::OsRng;
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        let suffix: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
        let path = std::env::temp_dir().join(format!("bsec-{}", suffix));
        std::fs::create_dir(&path).map_err(|e| anyhow!("creating staging dir: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        register_staged_dir(&path);
        Ok(Self { path })
    }

    #[allow(dead_code)] // part of the documented API; used in tests and by future callers
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write one already-decrypted member into the staging dir as a 0600 file; return its path.
    pub fn stage_member(&self, m: &BundleMember) -> Result<PathBuf> {
        let name = sanitize_basename(&m.filename)?;
        let path = self.path.join(name);
        let bytes = decode_body(&m.content, &m.encoding)?;
        crate::wallet::write_secure_file(&path, &bytes)?;
        // Register the exact file so a SIGINT/SIGTERM handler can unlink it (async-signal-safe)
        // before the staging dir is rmdir'd, even though Drop won't run on the `_exit` path.
        register_staged_file(&path);
        Ok(path)
    }
}

impl Drop for StagedDir {
    fn drop(&mut self) {
        // Normal / error exits wipe here. The signal registry is intentionally NOT pruned:
        // a stale path only means the async-signal handler later calls unlink/rmdir on an
        // already-removed path, which is a harmless ENOENT no-op.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Lock-free staged-path registry for async-signal-safe cleanup.
//
// A SIGINT/SIGTERM handler may only call async-signal-safe functions: no heap allocation,
// no std `Mutex`, no `opendir`/`readdir`/`remove_dir_all`. So instead of walking the dir in
// the handler, we pre-register the EXACT staged file and dir paths here (allocation happens in
// normal context), storing each as a leaked NUL-terminated C string behind an `AtomicPtr`. The
// handler then only reads those pointers and issues raw `unlink(2)`/`rmdir(2)`/`_exit(2)` — all
// async-signal-safe — wiping the plaintext even on a hard interrupt.
//
// Registrations are intentionally never freed or pruned: the pointers must stay valid for the
// process lifetime so the handler can read them, and a stale entry only makes the handler call
// unlink/rmdir on an already-removed path, a harmless ENOENT no-op. Capacity is bounded; on
// overflow a path simply isn't registered (Drop still wipes it on any non-signal exit).
// ---------------------------------------------------------------------------
#[cfg(unix)]
mod sigreg {
    use super::install_signal_cleanup;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    const FILE_CAP: usize = 1024;
    const DIR_CAP: usize = 64;

    pub(super) static FILES: [AtomicPtr<libc::c_char>; FILE_CAP] =
        [const { AtomicPtr::new(ptr::null_mut()) }; FILE_CAP];
    pub(super) static FILE_COUNT: AtomicUsize = AtomicUsize::new(0);
    pub(super) static DIRS: [AtomicPtr<libc::c_char>; DIR_CAP] =
        [const { AtomicPtr::new(ptr::null_mut()) }; DIR_CAP];
    pub(super) static DIR_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn register(reg: &[AtomicPtr<libc::c_char>], count: &AtomicUsize, path: &Path) {
        let c = match CString::new(path.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return, // path contains an interior NUL; cannot be a real staged path
        };
        let idx = count.fetch_add(1, Ordering::SeqCst);
        if idx < reg.len() {
            // Leak the C string on purpose: it must outlive every caller so the handler can read
            // it. `into_raw` hands ownership to the static slot; we never reclaim it.
            reg[idx].store(c.into_raw(), Ordering::SeqCst);
        } else {
            count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(super) fn register_file(path: &Path) {
        install_signal_cleanup();
        register(&FILES, &FILE_COUNT, path);
    }

    pub(super) fn register_dir(path: &Path) {
        install_signal_cleanup();
        register(&DIRS, &DIR_COUNT, path);
    }

    /// Async-signal-safe cleanup core: unlink each non-null FILE pointer, then rmdir each
    /// non-null DIR pointer. Uses only atomic loads and the async-signal-safe syscalls
    /// `unlink`/`rmdir` — no allocation, no lock, no directory walk. Parameterized over
    /// caller-supplied slices so it can be unit-tested with a local registry (the real handler
    /// passes the process-wide statics via `run_cleanup`).
    ///
    /// # Safety
    /// Every non-null pointer in `files[..nf]` / `dirs[..nd]` must be a valid NUL-terminated C
    /// string that stays valid for the duration of the call.
    pub(super) unsafe fn wipe(
        files: &[AtomicPtr<libc::c_char>],
        nf: usize,
        dirs: &[AtomicPtr<libc::c_char>],
        nd: usize,
    ) {
        for slot in &files[..nf.min(files.len())] {
            let p = slot.load(Ordering::SeqCst);
            if !p.is_null() {
                unsafe { libc::unlink(p) };
            }
        }
        for slot in &dirs[..nd.min(dirs.len())] {
            let p = slot.load(Ordering::SeqCst);
            if !p.is_null() {
                unsafe { libc::rmdir(p) };
            }
        }
    }

    /// Wipe every registered staged file/dir. Called from the signal handler.
    pub(super) fn run_cleanup() {
        let nf = FILE_COUNT.load(Ordering::SeqCst);
        let nd = DIR_COUNT.load(Ordering::SeqCst);
        unsafe { wipe(&FILES, nf, &DIRS, nd) };
    }
}

#[cfg(unix)]
fn register_staged_file(path: &Path) {
    sigreg::register_file(path);
}
#[cfg(not(unix))]
fn register_staged_file(_path: &Path) {}

#[cfg(unix)]
fn register_staged_dir(path: &Path) {
    sigreg::register_dir(path);
}
#[cfg(not(unix))]
fn register_staged_dir(_path: &Path) {}

#[cfg(unix)]
fn install_signal_cleanup() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let handler = signal_cleanup_handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    });
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn install_signal_cleanup() {}

/// SIGINT/SIGTERM handler. Async-signal-safe: it reads only atomic pointers and calls the
/// async-signal-safe syscalls `unlink`, `rmdir`, and `_exit`. It unlinks every registered staged
/// FILE, then rmdirs every registered staging DIR (now empty), then terminates with the
/// conventional 128+signal code. No heap allocation, no lock, no directory walk — so it cannot
/// deadlock against the main thread and leaves no plaintext behind on a hard interrupt. Ordinary
/// and error exits are still handled by `StagedDir`'s `Drop`.
#[cfg(unix)]
extern "C" fn signal_cleanup_handler(sig: libc::c_int) {
    sigreg::run_cleanup();
    unsafe { libc::_exit(128 + sig) };
}

/// If a decrypted secret carries file members or a file-kind body, stage them into a fresh
/// temp dir and return (guard, env map). Returns Ok(None) for plain env/untagged secrets so
/// the caller falls back to variable injection. Env-kind members are BOTH staged and parsed.
pub fn stage_and_envs(
    payload: &IpfsPayload,
) -> Result<Option<(StagedDir, std::collections::BTreeMap<String, String>)>> {
    // Materialize into an owned member list so single-file and bundle share one code path.
    let members: Vec<BundleMember> = if let Some(ms) = &payload.members {
        ms.clone()
    } else if let Some(kind) = payload.kind {
        if is_file_kind(kind) {
            let filename = payload.filename.clone().unwrap_or_else(|| default_filename(kind.as_format()).to_string());
            vec![BundleMember {
                kind,
                filename,
                content: payload.content.clone(),
                encoding: payload.content_encoding.clone().unwrap_or_else(|| "utf8".to_string()),
                env: None,
            }]
        } else {
            return Ok(None); // env-kind single secret -> inject vars, no staging
        }
    } else {
        return Ok(None); // untagged -> legacy env/json injection
    };

    let staged = StagedDir::new()?;
    let mut envs = std::collections::BTreeMap::new();
    for m in &members {
        let path = staged.stage_member(m)?;
        let abs = path.canonicalize().unwrap_or(path);
        let abs_str = abs.to_string_lossy().to_string();
        envs.insert(stem_env_key(&m.filename), abs_str.clone());
        if let Some(ref env_name) = m.env {
            envs.insert(env_name.clone(), abs_str.clone());
        }
        // env-kind members also contribute their KEY=VAL pairs to the child environment.
        if m.kind == SecretKind::Env && m.encoding == "utf8" {
            for (k, v) in crate::env_file::parse_env_content(&m.content) {
                envs.insert(k, v);
            }
        }
    }
    Ok(Some((staged, envs)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(content: &str, kind: Option<SecretKind>) -> IpfsPayload {
        IpfsPayload {
            content: content.to_string(),
            content_key: String::new(),
            ephemeral_pubkey: None,
            kind,
            filename: None,
            no_export: false,
            members: None,
            content_encoding: None,
        }
    }

    #[test]
    fn resolution_prefers_explicit_over_kind_over_sniff() {
        // explicit wins over kind
        assert_eq!(
            resolve_format(Some(OutputFormat::Pem), Some(SecretKind::Json), "{}"),
            OutputFormat::Pem
        );
        // kind wins over sniff
        assert_eq!(resolve_format(None, Some(SecretKind::Cred), "KEY=v"), OutputFormat::Cred);
        // sniff fallback
        assert_eq!(resolve_format(None, None, "-----BEGIN CERT-----"), OutputFormat::Pem);
        assert_eq!(resolve_format(None, None, "{\"a\":1}"), OutputFormat::Json);
        assert_eq!(resolve_format(None, None, "KEY=val"), OutputFormat::Env);
        assert_eq!(resolve_format(None, None, "just some opaque blob"), OutputFormat::Cred);
    }

    #[test]
    fn schema_env_sorted_keys_no_values() {
        let p = payload("ZED=last\nALPHA=secret\nBETA=hush", Some(SecretKind::Env));
        let s = extract_schema(&p).unwrap();
        assert_eq!(s, "ALPHA=\nBETA=\nZED=\n");
        assert!(!s.contains("secret"));
        assert!(!s.contains("hush"));
    }

    #[test]
    fn schema_json_keys() {
        let p = payload(r#"{"DB_URL":"postgres://secret","API_KEY":"xyz"}"#, Some(SecretKind::Json));
        let s = extract_schema(&p).unwrap();
        assert_eq!(s, "API_KEY=\nDB_URL=\n");
        assert!(!s.contains("secret"));
        assert!(!s.contains("xyz"));
    }

    #[test]
    fn schema_pem_errors() {
        let p = payload("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", Some(SecretKind::Pem));
        assert!(extract_schema(&p).is_err());
    }

    #[test]
    fn schema_blocked_when_no_export() {
        let mut p = payload("KEY=v", Some(SecretKind::Env));
        p.no_export = true;
        let err = extract_schema(&p).unwrap_err().to_string();
        assert!(err.contains("no-export"), "got: {}", err);
    }

    #[test]
    fn schema_rejects_binary_content() {
        let mut p = payload("AAAA", Some(SecretKind::Cred));
        p.content_encoding = Some("base64".to_string());
        assert!(extract_schema(&p).is_err());
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn single_writes_to_dir_with_filename_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = payload("KEY=val\nB=2", Some(SecretKind::Env));
        p.filename = Some(".env".to_string());
        let path = materialize_single(&p, OutputFormat::Env, OutTarget::Dir(dir.path().to_path_buf()), false).unwrap();
        assert_eq!(path, dir.path().join(".env"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "KEY=val\nB=2");
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn single_default_filename_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = payload("-----BEGIN CERT-----", Some(SecretKind::Pem));
        let path = materialize_single(&p, OutputFormat::Pem, OutTarget::Dir(dir.path().to_path_buf()), false).unwrap();
        assert_eq!(path.file_name().unwrap(), "cert.pem");
    }

    #[test]
    fn single_file_target_writes_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested").join("out.json");
        let p = payload(r#"{"a":1}"#, Some(SecretKind::Json));
        let path = materialize_single(&p, OutputFormat::Json, OutTarget::File(target.clone()), false).unwrap();
        assert_eq!(path, target);
        assert!(target.exists());
    }

    #[test]
    fn single_overwrite_guarded_then_forced() {
        let dir = tempfile::tempdir().unwrap();
        let p = payload("KEY=v", Some(SecretKind::Env));
        let t = OutTarget::Dir(dir.path().to_path_buf());
        materialize_single(&p, OutputFormat::Env, OutTarget::Dir(dir.path().to_path_buf()), false).unwrap();
        // second write without force fails
        let err = materialize_single(&p, OutputFormat::Env, t, false).unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "got: {}", err);
        // with force succeeds
        materialize_single(&p, OutputFormat::Env, OutTarget::Dir(dir.path().to_path_buf()), true).unwrap();
    }

    #[test]
    fn single_no_export_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = payload("x", Some(SecretKind::Cred));
        p.no_export = true;
        assert!(materialize_single(&p, OutputFormat::Cred, OutTarget::Dir(dir.path().to_path_buf()), false).is_err());
    }

    #[test]
    fn single_base64_body_decoded_to_raw_bytes() {
        use base64::prelude::*;
        let dir = tempfile::tempdir().unwrap();
        let raw: &[u8] = &[0u8, 1, 2, 255, 254];
        let mut p = payload(&BASE64_STANDARD.encode(raw), Some(SecretKind::Pem));
        p.content_encoding = Some("base64".to_string());
        p.filename = Some("key.bin".to_string());
        let path = materialize_single(&p, OutputFormat::Pem, OutTarget::Dir(dir.path().to_path_buf()), false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), raw);
    }

    #[test]
    fn single_rejects_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = payload("", None);
        p.members = Some(vec![]);
        assert!(materialize_single(&p, OutputFormat::Env, OutTarget::Dir(dir.path().to_path_buf()), false).is_err());
    }

    #[test]
    fn bundle_writes_all_members_0600() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = payload("", None);
        p.members = Some(vec![
            BundleMember { kind: SecretKind::Pem, filename: "cert.pem".into(), content: "PEMBODY".into(), encoding: "utf8".into(), env: None },
            BundleMember { kind: SecretKind::Env, filename: ".env".into(), content: "K=V".into(), encoding: "utf8".into(), env: None },
        ]);
        let out = dir.path().join("stage");
        let paths = materialize_bundle(&p, &out, false).unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(std::fs::read_to_string(out.join("cert.pem")).unwrap(), "PEMBODY");
        assert_eq!(std::fs::read_to_string(out.join(".env")).unwrap(), "K=V");
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&out.join("cert.pem")), 0o600);
            assert_eq!(mode_of(&out) & 0o777, 0o700);
        }
    }

    #[test]
    fn bundle_rejects_traversal_member() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = payload("", None);
        p.members = Some(vec![BundleMember {
            kind: SecretKind::Env, filename: "../escape".into(), content: "x".into(), encoding: "utf8".into(), env: None,
        }]);
        assert!(materialize_bundle(&p, dir.path(), false).is_err());
    }

    #[test]
    fn stem_env_key_forms() {
        assert_eq!(stem_env_key("service-account.json"), "SERVICE_ACCOUNT_FILE");
        assert_eq!(stem_env_key("cert.pem"), "CERT_FILE");
        assert_eq!(stem_env_key(".env"), "ENV_FILE");
        assert_eq!(stem_env_key("kubeconfig"), "KUBECONFIG_FILE");
    }

    #[test]
    fn stage_and_envs_none_for_env_and_untagged() {
        assert!(stage_and_envs(&payload("K=V", Some(SecretKind::Env))).unwrap().is_none());
        assert!(stage_and_envs(&payload("anything", None)).unwrap().is_none());
    }

    #[test]
    fn stage_and_envs_stages_bundle_with_file_and_env_vars() {
        let mut p = payload("", None);
        p.members = Some(vec![
            BundleMember { kind: SecretKind::Json, filename: "creds.json".into(), content: "{}".into(), encoding: "utf8".into(), env: Some("GOOGLE_APPLICATION_CREDENTIALS".into()) },
            BundleMember { kind: SecretKind::Env, filename: ".env".into(), content: "DB=postgres\nPORT=5432".into(), encoding: "utf8".into(), env: None },
        ]);
        let (staged, envs) = stage_and_envs(&p).unwrap().unwrap();
        // json member staged with its explicit env alias + stem key
        let creds = envs.get("GOOGLE_APPLICATION_CREDENTIALS").unwrap();
        assert!(std::path::Path::new(creds).exists());
        assert_eq!(envs.get("CREDS_FILE").unwrap(), creds);
        // env member both staged (ENV_FILE) and parsed into vars
        assert!(envs.contains_key("ENV_FILE"));
        assert_eq!(envs.get("DB").unwrap(), "postgres");
        assert_eq!(envs.get("PORT").unwrap(), "5432");
        // dir wiped on drop
        let dir = staged.path().to_path_buf();
        assert!(dir.exists());
        drop(staged);
        assert!(!dir.exists());
    }

    #[test]
    fn stage_and_envs_single_file_kind() {
        let mut p = payload("-----BEGIN CERT-----", Some(SecretKind::Pem));
        p.filename = Some("tls.pem".into());
        let (_staged, envs) = stage_and_envs(&p).unwrap().unwrap();
        assert!(envs.contains_key("TLS_FILE"));
    }

    #[test]
    fn infer_kind_from_extension() {
        assert_eq!(infer_kind(Path::new("a/.env")), SecretKind::Env);
        assert_eq!(infer_kind(Path::new(".env.prod")), SecretKind::Env);
        assert_eq!(infer_kind(Path::new("x.env")), SecretKind::Env);
        assert_eq!(infer_kind(Path::new("cert.pem")), SecretKind::Pem);
        assert_eq!(infer_kind(Path::new("server.crt")), SecretKind::Pem);
        assert_eq!(infer_kind(Path::new("tls.key")), SecretKind::Pem);
        assert_eq!(infer_kind(Path::new("creds.json")), SecretKind::Json);
        assert_eq!(infer_kind(Path::new("kubeconfig")), SecretKind::Cred);
    }

    #[test]
    fn read_file_body_utf8_and_binary() {
        let dir = tempfile::tempdir().unwrap();
        let text = dir.path().join("t.txt");
        std::fs::write(&text, "hello").unwrap();
        assert_eq!(read_file_body(&text).unwrap(), ("hello".to_string(), "utf8".to_string()));

        let bin = dir.path().join("b.bin");
        std::fs::write(&bin, [0u8, 159, 146, 150]).unwrap();
        let (body, enc) = read_file_body(&bin).unwrap();
        assert_eq!(enc, "base64");
        use base64::prelude::*;
        assert_eq!(BASE64_STANDARD.decode(body).unwrap(), vec![0u8, 159, 146, 150]);
    }

    #[test]
    fn load_bundle_members_reads_and_infers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cert.pem"), "PEMDATA").unwrap();
        std::fs::write(dir.path().join("app.json"), r#"{"k":1}"#).unwrap();
        let manifest = dir.path().join("bundle.json");
        std::fs::write(
            &manifest,
            r#"{"members":[
                {"path":"cert.pem"},
                {"path":"app.json","as":"json","filename":"creds.json","env":"GOOGLE_APPLICATION_CREDENTIALS"}
            ]}"#,
        )
        .unwrap();
        let members = load_bundle_members(&manifest).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].kind, SecretKind::Pem);
        assert_eq!(members[0].filename, "cert.pem");
        assert_eq!(members[0].content, "PEMDATA");
        assert_eq!(members[1].kind, SecretKind::Json);
        assert_eq!(members[1].filename, "creds.json");
        assert_eq!(members[1].env.as_deref(), Some("GOOGLE_APPLICATION_CREDENTIALS"));
    }

    #[test]
    fn load_bundle_rejects_traversal_filename() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), "x").unwrap();
        let manifest = dir.path().join("m.json");
        std::fs::write(&manifest, r#"{"members":[{"path":"f","filename":"../evil"}]}"#).unwrap();
        assert!(load_bundle_members(&manifest).is_err());
    }

    #[test]
    fn sanitize_accepts_plain_basename() {
        assert_eq!(sanitize_basename("cert.pem").unwrap(), "cert.pem");
        assert_eq!(sanitize_basename(".env").unwrap(), ".env");
        assert_eq!(sanitize_basename("service-account.json").unwrap(), "service-account.json");
    }

    #[test]
    fn sanitize_rejects_traversal_and_separators() {
        for bad in ["../x", "/etc/passwd", "a/b", "a\\b", "~/x", "..", ".", "", "x\0y"] {
            assert!(sanitize_basename(bad).is_err(), "should reject {:?}", bad);
        }
    }

    #[test]
    fn decode_utf8_passthrough() {
        assert_eq!(decode_body("KEY=val", "utf8").unwrap(), b"KEY=val");
    }

    #[test]
    fn decode_base64_roundtrip() {
        use base64::prelude::*;
        let raw: &[u8] = &[0u8, 159, 146, 150, 255, 1]; // non-utf8 bytes
        let encoded = BASE64_STANDARD.encode(raw);
        assert_eq!(decode_body(&encoded, "base64").unwrap(), raw);
    }

    #[test]
    fn decode_rejects_bad_base64() {
        assert!(decode_body("not*base64!", "base64").is_err());
    }

    #[test]
    fn decode_rejects_unknown_encoding() {
        assert!(decode_body("x", "rot13").is_err());
    }

    // The signal-cleanup path itself cannot be driven in-process (the handler ends in `_exit`),
    // so we test the async-signal-safe cleanup CORE (`sigreg::wipe`) that the handler delegates
    // to, over a local registry pointing at real files. This exercises the exact unlink+rmdir
    // logic that removes plaintext on a hard interrupt, deterministically and in isolation.
    #[cfg(unix)]
    #[test]
    fn sigreg_wipe_unlinks_files_then_rmdirs_dirs() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::sync::atomic::{AtomicPtr, Ordering};

        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join("bsec-stage");
        std::fs::create_dir(&stage).unwrap();
        let f1 = stage.join("secret.pem");
        let f2 = stage.join(".env");
        std::fs::write(&f1, b"PLAINTEXT-KEY").unwrap();
        std::fs::write(&f2, b"DB=secret").unwrap();
        assert!(f1.exists() && f2.exists() && stage.exists());

        let c_f1 = CString::new(f1.as_os_str().as_bytes()).unwrap();
        let c_f2 = CString::new(f2.as_os_str().as_bytes()).unwrap();
        let c_dir = CString::new(stage.as_os_str().as_bytes()).unwrap();
        let files = [AtomicPtr::new(c_f1.into_raw()), AtomicPtr::new(c_f2.into_raw())];
        let dirs = [AtomicPtr::new(c_dir.into_raw())];

        // SAFETY: all pointers are valid, NUL-terminated, and outlive the call.
        unsafe { super::sigreg::wipe(&files, files.len(), &dirs, dirs.len()) };

        assert!(!f1.exists(), "registered file should be unlinked");
        assert!(!f2.exists(), "registered file should be unlinked");
        assert!(!stage.exists(), "emptied staging dir should be rmdir'd");

        // Reclaim the leaked CStrings so the test doesn't leak (the real registry leaks on
        // purpose for process-lifetime validity; a test should not).
        unsafe {
            drop(CString::from_raw(files[0].load(Ordering::SeqCst)));
            drop(CString::from_raw(files[1].load(Ordering::SeqCst)));
            drop(CString::from_raw(dirs[0].load(Ordering::SeqCst)));
        }
    }

    // A null pointer in a slot must be skipped, not dereferenced (slots can be null mid-store or
    // beyond the live count).
    #[cfg(unix)]
    #[test]
    fn sigreg_wipe_skips_null_slots() {
        use std::sync::atomic::AtomicPtr;
        let files: [AtomicPtr<libc::c_char>; 1] = [AtomicPtr::new(std::ptr::null_mut())];
        let dirs: [AtomicPtr<libc::c_char>; 1] = [AtomicPtr::new(std::ptr::null_mut())];
        // Must not panic / segfault on null entries.
        unsafe { super::sigreg::wipe(&files, 1, &dirs, 1) };
    }

    // `register_staged_file` must record the exact path in the process-wide registry so the
    // handler can later unlink it. Scan the whole registry for our unique path (order- and
    // concurrency-independent).
    #[cfg(unix)]
    #[test]
    fn register_staged_file_records_path_in_registry() {
        use std::ffi::CStr;
        use std::sync::atomic::Ordering;

        let root = tempfile::tempdir().unwrap();
        let unique = root.path().join("uniq-8f3ac1-secret.txt");
        std::fs::write(&unique, b"x").unwrap();

        super::register_staged_file(&unique);

        let target = unique.to_string_lossy().to_string();
        let found = super::sigreg::FILES.iter().any(|slot| {
            let p = slot.load(Ordering::SeqCst);
            !p.is_null() && unsafe { CStr::from_ptr(p) }.to_string_lossy() == target
        });
        assert!(found, "registered staged file was not found in the signal registry");
    }
}
