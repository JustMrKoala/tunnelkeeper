//! config.toml. Holds no secrets. Cloudflare stays authoritative for routes,
//! the local copy lets `status` probe local apps while the API is unreachable.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::write_atomic;

pub const MIN_CLOUDFLARED: &str = "2025.4.0";
pub const FIRST_METRICS_PORT: u16 = 20301;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub cloudflared: CloudflaredConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default, rename = "tunnel", skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<TunnelConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CloudflaredConfig {
    /// `managed`, or an absolute path used as the install source.
    pub path: String,
    pub min_version: String,
}

impl Default for CloudflaredConfig {
    fn default() -> Self {
        CloudflaredConfig { path: "managed".into(), min_version: MIN_CLOUDFLARED.into() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UiConfig {
    pub port: u16,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig { port: 17844 }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TunnelConfig {
    pub name: String,
    pub id: String,
    pub account_id: String,
    pub metrics_port: u16,
    #[serde(default, rename = "route", skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RouteConfig {
    pub hostname: String,
    pub service: String,
    pub zone_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_record_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config { version: 1, cloudflared: Default::default(), ui: Default::default(), tunnels: vec![] }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(Error::io(format!("read {}", path.display()), e)),
        };
        let cfg: Config = toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        if cfg.version != 1 {
            return Err(Error::Config(format!("unsupported config version {}", cfg.version)));
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        write_atomic(path, text.as_bytes())
    }

    pub fn tunnel(&self, name: &str) -> Option<&TunnelConfig> {
        self.tunnels.iter().find(|t| t.name == name)
    }

    pub fn tunnel_mut(&mut self, name: &str) -> Option<&mut TunnelConfig> {
        self.tunnels.iter_mut().find(|t| t.name == name)
    }

    /// Resolves an optional `--tunnel` value. It may be left out when exactly
    /// one tunnel is configured.
    pub fn resolve_tunnel(&self, name: Option<&str>) -> Result<&TunnelConfig> {
        match name {
            Some(n) => self.tunnel(n).ok_or_else(|| Error::NotFound(format!("tunnel {n} is not in the config"))),
            None => match self.tunnels.as_slice() {
                [only] => Ok(only),
                [] => Err(Error::NotFound("no tunnels configured, run setup first".into())),
                _ => Err(Error::Invalid("several tunnels are configured, pass --tunnel".into())),
            },
        }
    }

    /// The first free port at or above the base. `is_free` asks the OS.
    pub fn next_metrics_port(&self, is_free: impl Fn(u16) -> bool) -> Result<u16> {
        (FIRST_METRICS_PORT..FIRST_METRICS_PORT + 500)
            .find(|p| !self.tunnels.iter().any(|t| t.metrics_port == *p) && is_free(*p))
            .ok_or_else(|| Error::Conflict("no free metrics port found".into()))
    }
}

/// Tunnel names become part of service names and file paths, so only a safe
/// character set is allowed.
pub fn validate_tunnel_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 40
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "invalid tunnel name {name:?}: use 1 to 40 lowercase letters, digits or hyphens, not starting or ending with a hyphen"
        )))
    }
}

pub fn normalize_hostname(hostname: &str) -> Result<String> {
    let h = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').collect();
    let ok = labels.len() >= 2
        && h.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        });
    if ok { Ok(h) } else { Err(Error::Invalid(format!("invalid hostname {hostname:?}"))) }
}

/// Accepts a port number or a full service URL.
pub fn normalize_service(target: &str) -> Result<String> {
    let t = target.trim();
    if let Ok(port) = t.parse::<u16>() {
        if port == 0 {
            return Err(Error::Invalid("port 0 is not valid".into()));
        }
        return Ok(format!("http://localhost:{port}"));
    }
    const SCHEMES: [&str; 9] =
        ["http://", "https://", "unix://", "tcp://", "ssh://", "rdp://", "unix+tls://", "smb://", "http_status:"];
    if SCHEMES.iter().any(|s| t.starts_with(s) && t.len() > s.len()) {
        Ok(t.to_string())
    } else {
        Err(Error::Invalid(format!("invalid target {target:?}: use a port number or a URL such as http://localhost:3000")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips() {
        let cfg = Config {
            tunnels: vec![TunnelConfig {
                name: "web".into(),
                id: "id".into(),
                account_id: "acct".into(),
                metrics_port: 20301,
                routes: vec![RouteConfig {
                    hostname: "app.example.com".into(),
                    service: "http://localhost:3000".into(),
                    zone_id: "z".into(),
                    dns_record_id: Some("r".into()),
                }],
            }],
            ..Config::default()
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), cfg);
    }

    #[test]
    fn missing_file_gives_default() {
        assert_eq!(Config::load(Path::new("does/not/exist.toml")).unwrap(), Config::default());
    }

    #[test]
    fn tunnel_names() {
        assert!(validate_tunnel_name("web-1").is_ok());
        for bad in ["", "Web", "a b", "-a", "a-", "a&b", "a\"b", "..", &"x".repeat(41)] {
            assert!(validate_tunnel_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hostnames() {
        assert_eq!(normalize_hostname("App.Example.com.").unwrap(), "app.example.com");
        for bad in ["localhost", "a..b", "-a.com", "a b.com", ""] {
            assert!(normalize_hostname(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn services() {
        assert_eq!(normalize_service("3000").unwrap(), "http://localhost:3000");
        assert_eq!(normalize_service("https://localhost:8443").unwrap(), "https://localhost:8443");
        for bad in ["0", "70000", "localhost:3000", "ftp://x", "http://"] {
            assert!(normalize_service(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn metrics_ports_skip_used_and_busy() {
        let mut cfg = Config::default();
        cfg.tunnels.push(TunnelConfig {
            name: "a".into(),
            id: "1".into(),
            account_id: "x".into(),
            metrics_port: 20301,
            routes: vec![],
        });
        assert_eq!(cfg.next_metrics_port(|p| p != 20302).unwrap(), 20303);
    }

    #[test]
    fn tunnel_resolution() {
        let mut cfg = Config::default();
        assert!(cfg.resolve_tunnel(None).is_err());
        for n in ["a", "b"] {
            cfg.tunnels.push(TunnelConfig {
                name: n.into(),
                id: n.into(),
                account_id: "x".into(),
                metrics_port: 1,
                routes: vec![],
            });
        }
        assert!(cfg.resolve_tunnel(None).is_err());
        assert_eq!(cfg.resolve_tunnel(Some("b")).unwrap().id, "b");
    }
}
