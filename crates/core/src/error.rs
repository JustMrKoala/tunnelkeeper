//! One error type for the whole core. Messages never contain secrets.

use std::fmt;

use crate::cloudflare::DnsRecord;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Cloudflare answered with an error.
    Api { status: u16, code: Option<i64>, message: String, route: String },
    /// No usable answer from a remote host.
    Network(String),
    Io { context: String, source: std::io::Error },
    Config(String),
    /// Bad input from the user.
    Invalid(String),
    /// Real state blocks the action and a person has to decide.
    Conflict(String),
    /// A DNS record already exists for this hostname and points elsewhere.
    DnsConflict { hostname: String, records: Vec<DnsRecord> },
    CloudflaredMissing(String),
    Auth(String),
    Permission(String),
    Secret(String),
    Service(String),
    Elevation(String),
    /// The plan no longer matches reality, so nothing was changed.
    StalePlan(String),
    NotFound(String),
}

impl Error {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io { context: context.into(), source }
    }
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::Api { status: 404, .. } | Error::NotFound(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Api { status, code, message, route } => match code {
                Some(c) => write!(f, "Cloudflare API error on {route}: HTTP {status}, code {c}: {message}"),
                None => write!(f, "Cloudflare API error on {route}: HTTP {status}: {message}"),
            },
            Error::Network(m) => write!(f, "network error: {m}"),
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Config(m) => write!(f, "config error: {m}"),
            Error::Invalid(m) => write!(f, "{m}"),
            Error::Conflict(m) => write!(f, "conflict: {m}"),
            Error::DnsConflict { hostname, records } => {
                write!(f, "{hostname} already has DNS records that do not point at this tunnel:")?;
                for r in records {
                    write!(f, " [{} {}]", r.record_type, r.content)?;
                }
                Ok(())
            }
            Error::CloudflaredMissing(m) => write!(f, "cloudflared problem: {m}"),
            Error::Auth(m) => write!(f, "authentication problem: {m}"),
            Error::Permission(m) => write!(f, "missing permission: {m}"),
            Error::Secret(m) => write!(f, "secret store error: {m}"),
            Error::Service(m) => write!(f, "service error: {m}"),
            Error::Elevation(m) => write!(f, "elevation error: {m}"),
            Error::StalePlan(m) => write!(f, "plan is out of date, nothing was changed: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
        }
    }
}

impl std::error::Error for Error {}
