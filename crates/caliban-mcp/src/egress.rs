//! Egress to tool servers.
//!
//! - **Only registered URLs.** The tool registry is the allowlist: a call goes to the URL of a
//!   server the tenant registered, never to an address a model, a tool result or a redirect names
//!   (redirects are not followed, proxies from the environment are not used).
//! - **Resolved once, pinned.** For each connection the host is resolved once, every address it
//!   resolves to is checked, and the connection is pinned to the first one: a DNS answer that
//!   changes between the check and the connection (DNS rebinding) cannot move it elsewhere. A
//!   host with any refused address is refused as a whole.
//! - **Always refused:** link-local addresses (`169.254.0.0/16`, `fe80::/10`, where cloud metadata
//!   services live), the known metadata addresses (`169.254.169.254`, `fd00:ec2::254`,
//!   `100.100.100.200`), unspecified, broadcast and multicast addresses, and loopback unless the
//!   deployment allows it (development and tests).
//! - **Private ranges are allowed** (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`, CGNAT):
//!   on-prem tool servers usually live there, and registering a server is the explicit,
//!   audited, human decision that allows one. SSRF protection here therefore means "nothing the
//!   tenant did not register", not "nothing private".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// What the deployment allows beyond registered servers on non-refused addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Allow loopback addresses (development, tests; `CALIBAN_MCP_ALLOW_LOOPBACK`). Off by
    /// default: a tenant-registered URL must not reach services on the gateway's own host.
    pub allow_loopback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    #[error("{0} is not a usable tool server URL: {1}")]
    BadUrl(String, String),
    #[error("{host} resolves to {ip}, which is refused: {why}")]
    Refused { host: String, ip: IpAddr, why: &'static str },
    #[error("{0} could not be resolved: {1}")]
    Resolve(String, String),
    #[error("building the HTTP client: {0}")]
    Client(String),
}

/// Resolves host names (the system resolver, or a fixed answer in tests).
#[async_trait::async_trait]
pub trait Resolve: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

pub struct SystemResolver;

#[async_trait::async_trait]
impl Resolve for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Why an address is refused (`None`: allowed).
pub fn refused(ip: IpAddr, policy: EgressPolicy) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => refused_v4(v4, policy),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return refused_v4(v4, policy);
            }
            if v6 == "fd00:ec2::254".parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED) {
                return Some("a cloud metadata address");
            }
            if v6.is_unspecified() {
                return Some("unspecified");
            }
            if v6.is_loopback() && !policy.allow_loopback {
                return Some("loopback (not allowed in this deployment)");
            }
            if v6.is_multicast() {
                return Some("multicast");
            }
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Some("link-local (where cloud metadata services live)");
            }
            None
        }
    }
}

fn refused_v4(v4: Ipv4Addr, policy: EgressPolicy) -> Option<&'static str> {
    if v4 == Ipv4Addr::new(169, 254, 169, 254) || v4 == Ipv4Addr::new(100, 100, 100, 200) {
        return Some("a cloud metadata address");
    }
    if v4.is_link_local() {
        return Some("link-local (where cloud metadata services live)");
    }
    if v4.is_unspecified() || v4.octets()[0] == 0 {
        return Some("unspecified");
    }
    if v4.is_broadcast() {
        return Some("broadcast");
    }
    if v4.is_multicast() {
        return Some("multicast");
    }
    if v4.is_loopback() && !policy.allow_loopback {
        return Some("loopback (not allowed in this deployment)");
    }
    None
}

/// Checks a server URL as registered: `http` or `https`, a host, no credentials in it, no
/// fragment; an IP literal must not be refused.
pub fn check_url(raw: &str, policy: EgressPolicy) -> Result<url::Url, EgressError> {
    let bad = |m: &str| EgressError::BadUrl(raw.to_owned(), m.to_owned());
    let u = url::Url::parse(raw).map_err(|e| bad(&e.to_string()))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(bad("only http and https are supported (no stdio servers)"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad("credentials do not belong in the URL; register them as the server's credential"));
    }
    if u.fragment().is_some() {
        return Err(bad("a fragment is not allowed"));
    }
    let host = u.host_str().ok_or_else(|| bad("no host"))?;
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>()
        && let Some(why) = refused(ip, policy)
    {
        return Err(EgressError::Refused { host: host.to_owned(), ip, why });
    }
    Ok(u)
}

/// Resolves the URL's host once, checks every address, and picks the one to pin.
pub async fn resolve_pinned(
    u: &url::Url,
    resolver: &dyn Resolve,
    policy: EgressPolicy,
) -> Result<SocketAddr, EgressError> {
    let host = u.host_str().unwrap_or_default().trim_matches(['[', ']']).to_owned();
    let port = u.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => resolver.resolve(&host, port).await.map_err(|e| EgressError::Resolve(host.clone(), e.to_string()))?,
    };
    if addrs.is_empty() {
        return Err(EgressError::Resolve(host, "no address".into()));
    }
    for a in &addrs {
        if let Some(why) = refused(a.ip(), policy) {
            return Err(EgressError::Refused { host, ip: a.ip(), why });
        }
    }
    Ok(addrs[0])
}

/// An HTTP client that can only reach `u`'s host at `addr` (resolved and checked by
/// [`resolve_pinned`]): no other DNS lookup, no redirects, no proxy.
pub fn pinned_client(u: &url::Url, addr: SocketAddr, timeout: Duration) -> Result<reqwest13::Client, EgressError> {
    let host = u.host_str().unwrap_or_default().trim_matches(['[', ']']).to_owned();
    let mut b = reqwest13::Client::builder()
        .redirect(reqwest13::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .tls_backend_preconfigured(tls_config()?);
    if host.parse::<IpAddr>().is_err() {
        b = b.resolve_to_addrs(&host, &[addr]);
    }
    b.build().map_err(|e| EgressError::Client(e.to_string()))
}

/// rustls with the ring provider (as the rest of the build) and the platform's trust store
/// (which honours `SSL_CERT_FILE` for an internal CA).
fn tls_config() -> Result<rustls::ClientConfig, EgressError> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| EgressError::Client(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| EgressError::Client(e.to_string()))
        .map(|b| b.with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Vec<IpAddr>);

    #[async_trait::async_trait]
    impl Resolve for Fixed {
        async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(self.0.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn metadata_link_local_and_loopback_are_refused_private_ranges_are_not() {
        let p = EgressPolicy::default();
        for bad in [
            "169.254.169.254",
            "169.254.10.1",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "::1",
            "224.0.0.1",
            "255.255.255.255",
            "::ffff:169.254.169.254",
        ] {
            assert!(refused(ip(bad), p).is_some(), "{bad}");
        }
        for ok in ["10.1.2.3", "172.16.0.9", "192.168.1.10", "100.64.0.1", "fd12::1", "93.184.216.34"] {
            assert_eq!(refused(ip(ok), p), None, "{ok}");
        }
        let dev = EgressPolicy { allow_loopback: true };
        assert_eq!(refused(ip("127.0.0.1"), dev), None);
        assert!(refused(ip("169.254.169.254"), dev).is_some(), "metadata stays refused");
    }

    #[test]
    fn urls_are_checked_when_registered() {
        let p = EgressPolicy::default();
        assert!(check_url("https://tools.internal:8443/mcp", p).is_ok());
        assert!(check_url("http://10.0.0.5/mcp", p).is_ok());
        for bad in [
            "file:///etc/passwd",
            "stdio://server",
            "https://user:pw@host/mcp",
            "http://169.254.169.254/latest",
            "https://host/mcp#x",
            "not a url",
            "http://[fe80::1]/mcp",
        ] {
            assert!(check_url(bad, p).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn every_resolved_address_is_checked() {
        let p = EgressPolicy::default();
        let u = check_url("https://tools.example/mcp", p).unwrap();
        let a = resolve_pinned(&u, &Fixed(vec![ip("10.0.0.7")]), p).await.unwrap();
        assert_eq!(a, "10.0.0.7:443".parse().unwrap());
        // One good and one metadata answer: refused as a whole.
        let e = resolve_pinned(&u, &Fixed(vec![ip("10.0.0.7"), ip("169.254.169.254")]), p).await.unwrap_err();
        assert!(matches!(e, EgressError::Refused { .. }), "{e}");
    }
}
