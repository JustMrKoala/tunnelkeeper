//! Secret handling.
//!
//! `Secret` deliberately has no `Debug`, `Display` or `Serialize`, so a token
//! cannot reach a log or a JSON response by accident:
//!
//! ```compile_fail
//! let s = tunnelkeeper_core::secret::Secret::new("x");
//! println!("{:?}", s);
//! ```
//!
//! ```compile_fail
//! let s = tunnelkeeper_core::secret::Secret::new("x");
//! println!("{}", s);
//! ```
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>(_: &T) {}
//! needs_serialize(&tunnelkeeper_core::secret::Secret::new("x"));
//! ```

use serde::{Deserialize, Deserializer, Serializer};

pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }
    /// The only way to read the value. Every call site is a place to audit.
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Secret(self.0.clone())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best effort wipe. Safe because zero bytes are valid UTF-8.
        unsafe {
            for b in self.0.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Secret(String::deserialize(d)?))
    }
}

/// Opt in serializer, used only for the privileged handoff file.
pub fn serialize_exposed<S: Serializer>(s: &Secret, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(s.expose())
}

const MASK: &str = "[REDACTED]";

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=' | '.')
}

/// Second layer of defence for text we did not produce, such as cloudflared
/// logs. Removes known values, anything after a credential keyword, tunnel
/// token shaped strings (base64 JSON starts with `eyJ`), and long opaque runs.
pub fn scrub(text: &str, known: &[&str]) -> String {
    let mut out = text.to_string();
    for k in known {
        if !k.is_empty() {
            out = out.replace(k, MASK);
        }
    }
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    let mut mask_next = false;
    while let Some(first) = rest.chars().next() {
        if is_token_char(first) {
            let end = rest.find(|c| !is_token_char(c)).unwrap_or(rest.len());
            let word = &rest[..end];
            rest = &rest[end..];
            if let Some(eq) = word.find('=').filter(|_| keyword_assignment(word)) {
                result.push_str(&word[..=eq]);
                result.push_str(MASK);
            } else if mask_next || looks_secret(word) {
                result.push_str(MASK);
            } else {
                result.push_str(word);
            }
            mask_next = is_keyword(word);
        } else {
            result.push(first);
            rest = &rest[first.len_utf8()..];
            if first != ' ' && first != ':' && first != '"' {
                mask_next = false;
            }
        }
    }
    result
}

fn is_keyword(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    matches!(w.as_str(), "bearer" | "--token" | "token" | "tunnel_token" | "tunneltoken" | "x-auth-key")
}

fn keyword_assignment(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    w.starts_with("--token=") || w.starts_with("token=") || w.starts_with("tunnel_token=")
}

fn looks_secret(word: &str) -> bool {
    let trimmed = word.trim_end_matches('=');
    let value = trimmed.rsplit('=').next().unwrap_or(trimmed);
    (value.starts_with("eyJ") && value.len() >= 20)
        || (value.len() >= 40 && !value.contains('/') && !value.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_known_values() {
        assert_eq!(scrub("value abc123 here", &["abc123"]), format!("value {MASK} here"));
    }

    #[test]
    fn scrubs_tunnel_token_shape() {
        let line = "run with eyJhIjoiNWFiNGU5ZDEyMyIsInQiOiJ4eXoifQ== now";
        assert!(!scrub(line, &[]).contains("eyJ"));
    }

    #[test]
    fn scrubs_after_keywords() {
        for line in ["--token shortvalue", "--token=shortvalue", "Authorization: Bearer shortvalue", "TUNNEL_TOKEN=shortvalue"] {
            assert!(!scrub(line, &[]).contains("shortvalue"), "{line}");
        }
    }

    #[test]
    fn keeps_ordinary_log_text() {
        let line = "2026-11-05T15:44:53Z INF Registered tunnel connection connIndex=0 ip=198.41.192.167 location=ams01 path=/some/file.log";
        assert_eq!(scrub(line, &[]), line);
    }

    #[test]
    fn keeps_uuids() {
        let line = "tunnelID=c1744f8b-faa1-48a4-9e5c-02ac921467fa";
        assert_eq!(scrub(line, &[]), line);
    }
}
