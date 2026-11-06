//! Local probes and the classification of tunnel health.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::service::{ServiceInfo, ServiceState};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum ReadyProbe {
    /// `/ready` answered 200.
    Ready { connections: u64, connector_id: Option<String> },
    /// `/ready` answered, but there are no edge connections.
    NotReady,
    /// Nothing is listening on the metrics port.
    Unreachable,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case", tag = "result", content = "detail")]
pub enum OriginProbe {
    Responding,
    NotResponding(String),
    /// This kind of service cannot be probed from here.
    Unchecked(String),
}

pub trait Probes: Send {
    fn ready(&self, metrics_port: u16) -> ReadyProbe;
    fn origin(&self, service: &str) -> OriginProbe;
    fn port_free(&self, port: u16) -> bool;
    fn resolves(&self, host: &str) -> bool;
    fn tcp_reachable(&self, host: &str, port: u16) -> bool;
}

pub struct RealProbes;

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|e| e.to_string())?.collect();
    let mut last = format!("no address found for {host}");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// A plain socket request. Using the HTTP client here would pick up proxy
/// settings, which must never apply to local probes.
fn http_exchange(stream: &mut TcpStream, method: &str, path: &str, host: &str) -> Result<(u16, String), String> {
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).map_err(|e| e.to_string())?;
    let request = format!("{method} {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: tunnelkeeper\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 256 * 1024 {
                    break;
                }
            }
            Err(e) if raw.is_empty() => return Err(e.to_string()),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .strip_prefix("HTTP/")
        .and_then(|t| t.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "not an HTTP response".to_string())?;
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((status, body))
}

/// Splits `http://host:port/path` into scheme, host and port.
pub fn parse_service(service: &str) -> Option<(String, String, u16)> {
    let (scheme, rest) = service.split_once("://")?;
    let authority = rest.split('/').next()?;
    let default_port = match scheme {
        "http" => Some(80),
        "https" => Some(443),
        "ssh" => Some(22),
        "rdp" => Some(3389),
        "smb" => Some(445),
        _ => None,
    };
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (h, tail) = stripped.split_once(']')?;
        (h.to_string(), tail.strip_prefix(':').and_then(|p| p.parse().ok()).or(default_port)?)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default_port?),
        }
    };
    Some((scheme.to_string(), host, port))
}

impl Probes for RealProbes {
    fn ready(&self, metrics_port: u16) -> ReadyProbe {
        let Ok(mut stream) = connect("127.0.0.1", metrics_port) else {
            return ReadyProbe::Unreachable;
        };
        match http_exchange(&mut stream, "GET", "/ready", "127.0.0.1") {
            Ok((200, body)) => {
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                ReadyProbe::Ready {
                    connections: v.get("readyConnections").and_then(Value::as_u64).unwrap_or(0),
                    connector_id: v.get("connectorId").and_then(Value::as_str).map(str::to_string),
                }
            }
            Ok(_) => ReadyProbe::NotReady,
            Err(_) => ReadyProbe::Unreachable,
        }
    }

    fn origin(&self, service: &str) -> OriginProbe {
        let Some((scheme, host, port)) = parse_service(service) else {
            return OriginProbe::Unchecked(format!("cannot probe {service}"));
        };
        let mut stream = match connect(&host, port) {
            Ok(s) => s,
            Err(e) => return OriginProbe::NotResponding(format!("cannot connect to {host}:{port}: {e}")),
        };
        if scheme != "http" {
            return OriginProbe::Responding;
        }
        // Any HTTP reply counts, even a 500, because the app is up.
        match http_exchange(&mut stream, "HEAD", "/", &host) {
            Ok(_) => OriginProbe::Responding,
            Err(e) => OriginProbe::NotResponding(format!("{host}:{port} accepted the connection but gave no HTTP reply: {e}")),
        }
    }

    fn port_free(&self, port: u16) -> bool {
        TcpListener::bind(("127.0.0.1", port)).is_ok()
    }

    fn resolves(&self, host: &str) -> bool {
        (host, 443).to_socket_addrs().is_ok_and(|mut a| a.next().is_some())
    }

    fn tcp_reachable(&self, host: &str, port: u16) -> bool {
        connect(host, port).is_ok()
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TunnelState {
    NotInstalled,
    ServiceStopped,
    TunnelDown,
    OriginDown,
    Degraded,
    Healthy,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RouteStatus {
    pub hostname: String,
    pub service: String,
    pub origin: OriginProbe,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RemoteStatus {
    /// inactive, degraded, healthy or down, as Cloudflare reports it.
    pub status: Option<String>,
    pub connectors: usize,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct TunnelStatus {
    pub name: String,
    pub id: String,
    pub state: TunnelState,
    pub message: String,
    pub service: ServiceInfo,
    pub ready: ReadyProbe,
    pub remote: Option<RemoteStatus>,
    /// Why the remote part is missing, when it is.
    pub remote_error: Option<String>,
    pub routes: Vec<RouteStatus>,
}

/// Decides the single headline state. Service state wins, then the link to
/// Cloudflare, then the local apps.
pub fn classify(
    service: ServiceState,
    ready: &ReadyProbe,
    remote: Option<&RemoteStatus>,
    routes: &[RouteStatus],
) -> (TunnelState, String) {
    let elsewhere = remote.is_some_and(|r| r.connectors > 0);
    match service {
        ServiceState::Missing => {
            let mut m = "The service is not installed. Run: tunnelkeeper service install".to_string();
            if elsewhere {
                m.push_str(". Note: Cloudflare sees a connector for this tunnel, so it is running somewhere else");
            }
            return (TunnelState::NotInstalled, m);
        }
        ServiceState::Stopped | ServiceState::Stopping | ServiceState::Other => {
            let mut m = "The service is stopped. Run: tunnelkeeper service start".to_string();
            if elsewhere {
                m.push_str(". Note: Cloudflare still sees a connector, which may be another machine or a connection that has not expired yet");
            }
            return (TunnelState::ServiceStopped, m);
        }
        ServiceState::Starting | ServiceState::Running => {}
    }
    if !matches!(ready, ReadyProbe::Ready { .. }) {
        let detail = match ready {
            ReadyProbe::Unreachable => "cloudflared is not answering on its metrics port",
            _ => "cloudflared has no connection to Cloudflare",
        };
        return (TunnelState::TunnelDown, format!("The service is running but the tunnel is down: {detail}. Run: tunnelkeeper doctor"));
    }
    let down: Vec<&RouteStatus> = routes.iter().filter(|r| matches!(r.origin, OriginProbe::NotResponding(_))).collect();
    if !down.is_empty() {
        let names: Vec<String> = down.iter().map(|r| format!("{} ({})", r.hostname, r.service)).collect();
        return (
            TunnelState::OriginDown,
            format!("The tunnel is healthy but the local app is not responding: {}", names.join(", ")),
        );
    }
    if remote.and_then(|r| r.status.as_deref()) == Some("degraded") {
        return (TunnelState::Degraded, "The tunnel is serving traffic, but Cloudflare reports it as degraded".to_string());
    }
    (TunnelState::Healthy, "The tunnel and all local apps are healthy".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> ReadyProbe {
        ReadyProbe::Ready { connections: 4, connector_id: None }
    }

    fn route(origin: OriginProbe) -> RouteStatus {
        RouteStatus { hostname: "a.x.com".into(), service: "http://localhost:1".into(), origin }
    }

    fn remote(status: &str, connectors: usize) -> RemoteStatus {
        RemoteStatus { status: Some(status.into()), connectors }
    }

    #[test]
    fn three_required_states_are_distinct() {
        let down = route(OriginProbe::NotResponding("x".into()));
        let (a, _) = classify(ServiceState::Stopped, &ReadyProbe::Unreachable, None, &[]);
        let (b, _) = classify(ServiceState::Running, &ReadyProbe::NotReady, None, &[]);
        let (c, _) = classify(ServiceState::Running, &ready(), None, &[down]);
        assert_eq!(a, TunnelState::ServiceStopped);
        assert_eq!(b, TunnelState::TunnelDown);
        assert_eq!(c, TunnelState::OriginDown);
    }

    #[test]
    fn stopped_service_wins_over_stale_healthy_remote() {
        let r = remote("healthy", 1);
        let (s, m) = classify(ServiceState::Stopped, &ReadyProbe::Unreachable, Some(&r), &[]);
        assert_eq!(s, TunnelState::ServiceStopped);
        assert!(m.contains("connector"));
    }

    #[test]
    fn running_process_without_metrics_is_tunnel_down() {
        assert_eq!(classify(ServiceState::Running, &ReadyProbe::Unreachable, None, &[]).0, TunnelState::TunnelDown);
    }

    #[test]
    fn missing_service() {
        assert_eq!(classify(ServiceState::Missing, &ReadyProbe::Unreachable, None, &[]).0, TunnelState::NotInstalled);
    }

    #[test]
    fn degraded_and_healthy() {
        let ok = [route(OriginProbe::Responding)];
        assert_eq!(classify(ServiceState::Running, &ready(), Some(&remote("degraded", 1)), &ok).0, TunnelState::Degraded);
        assert_eq!(classify(ServiceState::Running, &ready(), Some(&remote("healthy", 1)), &ok).0, TunnelState::Healthy);
    }

    #[test]
    fn local_health_works_without_the_api() {
        let ok = [route(OriginProbe::Responding)];
        assert_eq!(classify(ServiceState::Running, &ready(), None, &ok).0, TunnelState::Healthy);
    }

    #[test]
    fn unchecked_origin_is_not_a_failure() {
        let r = [route(OriginProbe::Unchecked("unix".into()))];
        assert_eq!(classify(ServiceState::Running, &ready(), None, &r).0, TunnelState::Healthy);
    }

    #[test]
    fn parses_service_urls() {
        assert_eq!(parse_service("http://localhost:3000"), Some(("http".into(), "localhost".into(), 3000)));
        assert_eq!(parse_service("https://example.internal/x"), Some(("https".into(), "example.internal".into(), 443)));
        assert_eq!(parse_service("http://[::1]:8080"), Some(("http".into(), "::1".into(), 8080)));
        assert_eq!(parse_service("unix:///tmp/s"), None);
        assert_eq!(parse_service("http_status:404"), None);
    }

    fn serve_once(reply: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(reply.as_bytes());
            }
        });
        port
    }

    #[test]
    fn real_ready_probe_reads_cloudflared_format() {
        let port = serve_once("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":200,\"readyConnections\":4,\"connectorId\":\"abc\"}");
        assert_eq!(RealProbes.ready(port), ReadyProbe::Ready { connections: 4, connector_id: Some("abc".into()) });
    }

    #[test]
    fn real_ready_probe_sees_503() {
        let port = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n{\"status\":503,\"readyConnections\":0}");
        assert_eq!(RealProbes.ready(port), ReadyProbe::NotReady);
    }

    #[test]
    fn real_ready_probe_sees_nothing_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(RealProbes.ready(port), ReadyProbe::Unreachable);
    }

    #[test]
    fn real_origin_probe_counts_500_as_up() {
        let port = serve_once("HTTP/1.1 500 Internal Server Error\r\n\r\n");
        assert_eq!(RealProbes.origin(&format!("http://127.0.0.1:{port}")), OriginProbe::Responding);
    }

    #[test]
    fn real_origin_probe_sees_refused_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(matches!(RealProbes.origin(&format!("http://127.0.0.1:{port}")), OriginProbe::NotResponding(_)));
    }

    #[test]
    fn real_origin_probe_sees_hung_app() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(RealProbes.origin(&format!("http://127.0.0.1:{port}")), OriginProbe::NotResponding(_)));
        drop(listener);
    }

    #[test]
    fn port_free_detects_a_taken_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(!RealProbes.port_free(listener.local_addr().unwrap().port()));
    }
}
