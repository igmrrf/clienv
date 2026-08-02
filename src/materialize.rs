use anyhow::{anyhow, Result};

use crate::secrets::{IpfsPayload, SecretKind};

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
}
