use anyhow::{anyhow, Result};

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

#[cfg(test)]
mod tests {
    use super::*;

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
