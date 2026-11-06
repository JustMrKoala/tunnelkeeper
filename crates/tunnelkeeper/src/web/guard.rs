//! Request checks. Pure functions, so each attack is easy to test.
//!
//! * DNS rebinding: `Host` must be exactly our address. A rebound name such as
//!   evil.example:17844 reaches this socket but fails here.
//! * Cross site requests: state changes need a matching `Origin`,
//!   `Sec-Fetch-Site: same-origin`, a JSON content type and a CSRF header.
//!   No CORS headers are ever sent.
//! * Other local users and programs: every route needs the session cookie,
//!   which is only given out for the one time launch token.

pub const SESSION_COOKIE: &str = "tk_session";
pub const CSRF_HEADER: &str = "X-TK-CSRF";

#[derive(Default, Debug, Clone)]
pub struct RequestFacts {
    pub post: bool,
    pub host: Option<String>,
    pub origin: Option<String>,
    pub sec_fetch_site: Option<String>,
    pub content_type: Option<String>,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Denied {
    pub status: u16,
    pub reason: &'static str,
}

pub struct Secrets<'a> {
    pub port: u16,
    pub session: &'a str,
    pub csrf: &'a str,
}

/// Comparison that does not stop at the first different byte.
pub fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Checks that apply before anything else, on every request.
pub fn check_origin_rules(r: &RequestFacts, port: u16) -> Result<(), Denied> {
    let host = r.host.as_deref().unwrap_or("");
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        return Err(Denied { status: 403, reason: "unexpected Host header" });
    }
    if matches!(r.sec_fetch_site.as_deref(), Some("cross-site" | "same-site")) {
        return Err(Denied { status: 403, reason: "cross site request refused" });
    }
    if r.origin.as_deref().is_some_and(|o| o != format!("http://{host}")) {
        return Err(Denied { status: 403, reason: "unexpected Origin header" });
    }
    Ok(())
}

pub fn has_session(r: &RequestFacts, session: &str) -> bool {
    r.cookie.as_deref().and_then(|c| cookie_value(c, SESSION_COOKIE)).is_some_and(|v| same(v, session))
}

/// All checks for a route that needs a session.
pub fn check(r: &RequestFacts, s: &Secrets) -> Result<(), Denied> {
    check_origin_rules(r, s.port)?;
    if !has_session(r, s.session) {
        return Err(Denied { status: 401, reason: "no session. Open the link printed by tunnelkeeper ui" });
    }
    if r.post {
        if r.origin.is_none() {
            return Err(Denied { status: 403, reason: "missing Origin header" });
        }
        if r.sec_fetch_site.as_deref() != Some("same-origin") {
            return Err(Denied { status: 403, reason: "request is not same origin" });
        }
        if !r.content_type.as_deref().is_some_and(|c| c.starts_with("application/json")) {
            return Err(Denied { status: 415, reason: "content type must be JSON" });
        }
        if !r.csrf.as_deref().is_some_and(|c| same(c, s.csrf)) {
            return Err(Denied { status: 403, reason: "missing or wrong CSRF token" });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Secrets = Secrets { port: 17844, session: "sess", csrf: "tok" };

    fn get() -> RequestFacts {
        RequestFacts { host: Some("127.0.0.1:17844".into()), cookie: Some(format!("{SESSION_COOKIE}=sess")), ..Default::default() }
    }

    fn post() -> RequestFacts {
        RequestFacts {
            post: true,
            origin: Some("http://127.0.0.1:17844".into()),
            sec_fetch_site: Some("same-origin".into()),
            content_type: Some("application/json".into()),
            csrf: Some("tok".into()),
            ..get()
        }
    }

    #[test]
    fn honest_requests_pass() {
        assert_eq!(check(&get(), &S), Ok(()));
        assert_eq!(check(&post(), &S), Ok(()));
    }

    #[test]
    fn localhost_works_with_its_own_origin() {
        let r = RequestFacts { host: Some("localhost:17844".into()), origin: Some("http://localhost:17844".into()), ..post() };
        assert_eq!(check(&r, &S), Ok(()));
    }

    #[test]
    fn dns_rebinding_hosts_are_refused() {
        for host in ["evil.example:17844", "evil.example", "127.0.0.1", "127.0.0.1:1", "127.0.0.1:17844.evil.example", "LOCALHOST:17844.", "[::1]:17844", "0.0.0.0:17844", ""] {
            let r = RequestFacts { host: Some(host.into()), ..get() };
            assert_eq!(check(&r, &S).unwrap_err().status, 403, "{host}");
        }
        let r = RequestFacts { host: None, ..get() };
        assert_eq!(check(&r, &S).unwrap_err().status, 403);
    }

    #[test]
    fn foreign_origins_are_refused() {
        for origin in ["http://evil.example", "https://127.0.0.1:17844", "http://127.0.0.1:1", "null", "http://localhost:17844"] {
            let r = RequestFacts { origin: Some(origin.into()), ..post() };
            assert_eq!(check(&r, &S).unwrap_err().status, 403, "{origin}");
        }
    }

    #[test]
    fn cross_site_fetch_metadata_is_refused_even_for_reads() {
        for site in ["cross-site", "same-site"] {
            let r = RequestFacts { sec_fetch_site: Some(site.into()), ..get() };
            assert_eq!(check(&r, &S).unwrap_err().status, 403);
        }
    }

    #[test]
    fn each_write_requirement_is_enforced() {
        let cases = [
            RequestFacts { origin: None, ..post() },
            RequestFacts { sec_fetch_site: None, ..post() },
            RequestFacts { sec_fetch_site: Some("none".into()), ..post() },
            RequestFacts { csrf: None, ..post() },
            RequestFacts { csrf: Some("wrong".into()), ..post() },
        ];
        for r in cases {
            assert_eq!(check(&r, &S).unwrap_err().status, 403, "{r:?}");
        }
        for ct in [None, Some("text/plain".to_string()), Some("application/x-www-form-urlencoded".to_string()), Some("multipart/form-data".to_string())] {
            let r = RequestFacts { content_type: ct, ..post() };
            assert_eq!(check(&r, &S).unwrap_err().status, 415);
        }
    }

    #[test]
    fn session_is_required() {
        for cookie in [None, Some("other=1".to_string()), Some(format!("{SESSION_COOKIE}=wrong")), Some(format!("x{SESSION_COOKIE}=sess"))] {
            let r = RequestFacts { cookie, ..get() };
            assert_eq!(check(&r, &S).unwrap_err().status, 401);
        }
    }

    #[test]
    fn cookie_parsing() {
        assert_eq!(cookie_value("a=1; tk_session=abc; b=2", SESSION_COOKIE), Some("abc"));
        assert_eq!(cookie_value("a=1", SESSION_COOKIE), None);
    }

    #[test]
    fn comparison() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
    }
}
