//! Ordered user routing rules (process / domain / IP / catch-all).
//!
//! Rules are compiled once when the tunnel starts and are evaluated in order;
//! the first enabled match wins. When nothing matches the caller falls back to
//! the built-in RU/non-RU split routing, so custom rules are purely an
//! override layer on top of it.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::store::RoutingRule;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Proxy,
    Direct,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Process,
    Domain,
    Ip,
    All,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    kind: Kind,
    action: RuleAction,
    /// Named route for [`RuleAction::Proxy`].
    route: Option<String>,
    /// Normalized process name (lowercase, no directory, no `.exe`).
    process: String,
    /// Normalized domain suffix (lowercase, no leading `*.`/`.`).
    domain: String,
    /// CIDR list for `ip` rules.
    nets: Vec<IpNet>,
}

impl CompiledRule {
    fn describe(&self) -> String {
        match self.kind {
            Kind::Process => format!("process {}", self.process),
            Kind::Domain => format!("domain {}", self.domain),
            Kind::Ip => {
                let nets: Vec<String> = self.nets.iter().map(|net| net.to_string()).collect();
                format!("ip {}", nets.join(","))
            }
            Kind::All => "all traffic".to_owned(),
        }
    }
}

/// Result of a successful rule match.
#[derive(Clone, Debug)]
pub struct RuleMatch {
    pub action: RuleAction,
    pub route: Option<String>,
    /// Human-readable description used in log messages.
    pub rule: String,
}

/// Everything the policy needs to know about one connection.
pub struct TrafficContext<'a> {
    /// Host name if known, otherwise the destination IP as a string.
    pub host: &'a str,
    /// Destination IP, when it is already known.
    pub ip: Option<IpAddr>,
    /// Owning process name (`chrome.exe`), when it can be determined.
    pub process: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    rules: Vec<CompiledRule>,
}

impl Policy {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Compiles the user rules, dropping disabled and malformed entries.
    pub fn compile(rules: &[RoutingRule]) -> Self {
        let mut compiled = Vec::new();
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            match compile_rule(rule) {
                Some(rule) => compiled.push(rule),
                None => {}
            }
        }
        Self { rules: compiled }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn has_process_rules(&self) -> bool {
        self.rules.iter().any(|rule| rule.kind == Kind::Process)
    }

    /// Returns the first matching rule, if any.
    pub fn decide(&self, ctx: &TrafficContext<'_>) -> Option<RuleMatch> {
        let host = ctx.host.trim().trim_end_matches('.').to_ascii_lowercase();
        let ip = ctx
            .ip
            .or_else(|| host.parse::<IpAddr>().ok());
        let process = ctx.process.map(normalize_process);
        for rule in &self.rules {
            let matched = match rule.kind {
                Kind::All => true,
                Kind::Process => process
                    .as_deref()
                    .map(|name| process_matches(&rule.process, name))
                    .unwrap_or(false),
                Kind::Domain => {
                    // IP literals are handled by `ip` rules only, so a domain
                    // rule never accidentally matches a raw address.
                    !host.is_empty()
                        && host.parse::<IpAddr>().is_err()
                        && domain_matches(&rule.domain, &host)
                }
                Kind::Ip => ip
                    .as_ref()
                    .map(|ip| rule.nets.iter().any(|net| net.contains(ip)))
                    .unwrap_or(false),
            };
            if matched {
                return Some(RuleMatch {
                    action: rule.action,
                    route: rule.route.clone(),
                    rule: rule.describe(),
                });
            }
        }
        None
    }
}

fn compile_rule(rule: &RoutingRule) -> Option<CompiledRule> {
    let kind = match rule.kind.trim().to_ascii_lowercase().as_str() {
        "process" | "app" | "application" | "exe" => Kind::Process,
        "domain" | "host" | "hostname" => Kind::Domain,
        "ip" | "cidr" | "subnet" => Kind::Ip,
        "all" | "any" | "*" => Kind::All,
        other => {
            tracing::warn!("routing rule: unknown kind {other:?}, ignoring");
            return None;
        }
    };
    let action = match rule.action.trim().to_ascii_lowercase().as_str() {
        "proxy" | "vpn" | "tunnel" => RuleAction::Proxy,
        "direct" | "bypass" => RuleAction::Direct,
        "block" | "deny" | "reject" => RuleAction::Block,
        other => {
            tracing::warn!("routing rule: unknown action {other:?}, ignoring");
            return None;
        }
    };
    let route = rule
        .route
        .as_deref()
        .map(str::trim)
        .filter(|route| !route.is_empty())
        .map(str::to_owned);

    match kind {
        Kind::Process => {
            let process = normalize_process(&rule.value);
            if process.is_empty() {
                tracing::warn!("routing rule: empty process name, ignoring");
                return None;
            }
            Some(CompiledRule {
                kind,
                action,
                route,
                process,
                domain: String::new(),
                nets: Vec::new(),
            })
        }
        Kind::Domain => {
            let domain = normalize_domain(&rule.value);
            if domain.is_empty() {
                tracing::warn!("routing rule: empty domain, ignoring");
                return None;
            }
            Some(CompiledRule {
                kind,
                action,
                route,
                process: String::new(),
                domain,
                nets: Vec::new(),
            })
        }
        Kind::Ip => {
            let nets = parse_nets(&rule.value);
            if nets.is_empty() {
                tracing::warn!("routing rule: {:?} is not a valid IP or CIDR, ignoring", rule.value);
                return None;
            }
            Some(CompiledRule {
                kind,
                action,
                route,
                process: String::new(),
                domain: String::new(),
                nets,
            })
        }
        Kind::All => Some(CompiledRule {
            kind,
            action,
            route,
            process: String::new(),
            domain: String::new(),
            nets: Vec::new(),
        }),
    }
}

fn normalize_process(value: &str) -> String {
    let value = value.trim();
    let base = value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_owned()
}

fn normalize_domain(value: &str) -> String {
    let mut value = value.trim().to_ascii_lowercase();
    value = value.trim_end_matches('.').to_owned();
    if let Some(stripped) = value.strip_prefix("*.") {
        value = stripped.to_owned();
    }
    value.trim_start_matches('.').to_owned()
}

fn parse_nets(value: &str) -> Vec<IpNet> {
    let mut nets = Vec::new();
    for token in value.split([',', ' ', ';', '\n', '\t']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(net) = token.parse::<IpNet>() {
            nets.push(net);
        } else if let Ok(ip) = token.parse::<IpAddr>() {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            if let Ok(net) = IpNet::new(ip, prefix) {
                nets.push(net);
            }
        } else {
            tracing::warn!("routing rule: ignoring invalid network {token:?}");
        }
    }
    nets
}

/// Suffix match: `example.com` matches `example.com` and `a.example.com`.
/// A pattern with `*`/`?` is treated as a glob over the whole host.
fn domain_matches(pattern: &str, host: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        return glob_matches(pattern, host);
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn process_matches(pattern: &str, process: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        glob_matches(pattern, process)
    } else {
        pattern == process
    }
}

/// Minimal `*` / `?` wildcard matcher (no escaping, case-sensitive input is
/// already lowercased by the caller).
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(star_pi) = star {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Returns the executable name (lowercase, without `.exe`) that owns the local
/// TCP port. Used by the TUN runtime to match `process` rules.
///
/// Only Windows has a process table; other builds simply report `None`, which
/// leaves process rules inactive instead of failing to compile.
#[cfg(all(windows, feature = "gui"))]
pub fn process_for_port(port: u16) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };

    const AF_INET: u32 = 2;
    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    // First call sizes the table.
    let mut size = 0u32;
    let rc = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc == NO_ERROR {
        return None; // empty table
    }
    if rc != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    let mut buf = vec![0u32; (size as usize + 3) / 4];
    let mut rc = rc;
    for _ in 0..3 {
        rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut size,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == NO_ERROR {
            break;
        }
        if rc == ERROR_INSUFFICIENT_BUFFER {
            buf.resize((size as usize + 3) / 4, 0);
            continue;
        }
        return None;
    }
    if rc != NO_ERROR {
        return None;
    }

    // SAFETY: the buffer holds a MIB_TCPTABLE_OWNER_PID returned by the API.
    let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let rows = unsafe {
        let count = (*table).dwNumEntries as usize;
        std::slice::from_raw_parts((*table).table.as_ptr(), count)
    };
    for row in rows {
        // `dwLocalPort` keeps the port in network byte order in the low word.
        if u16::from_be(row.dwLocalPort as u16) != port {
            continue;
        }
        if let Some(name) = process_name(row.dwOwningPid) {
            return Some(name);
        }
    }
    None
}

#[cfg(all(windows, feature = "gui"))]
fn process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return None;
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(handle) };
    if ok == 0 || len == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buf[..len as usize]);
    Some(normalize_process(&path))
}

#[cfg(not(all(windows, feature = "gui")))]
pub fn process_for_port(_port: u16) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: &str, value: &str, action: &str) -> RoutingRule {
        RoutingRule {
            enabled: true,
            kind: kind.into(),
            value: value.into(),
            action: action.into(),
            route: None,
        }
    }

    fn ctx<'a>(host: &'a str, ip: Option<IpAddr>, process: Option<&'a str>) -> TrafficContext<'a> {
        TrafficContext { host, ip, process }
    }

    #[test]
    fn domain_suffix_and_wildcard() {
        let policy = Policy::compile(&[rule("domain", "example.com", "proxy")]);
        assert_eq!(
            policy.decide(&ctx("example.com", None, None)).map(|m| m.action),
            Some(RuleAction::Proxy)
        );
        assert_eq!(
            policy.decide(&ctx("a.b.example.com", None, None)).map(|m| m.action),
            Some(RuleAction::Proxy)
        );
        assert!(policy.decide(&ctx("notexample.com", None, None)).is_none());

        let policy = Policy::compile(&[rule("domain", "ads*.example.com", "block")]);
        assert_eq!(
            policy.decide(&ctx("ads1.example.com", None, None)).map(|m| m.action),
            Some(RuleAction::Block)
        );
    }

    #[test]
    fn ip_and_cidr_match() {
        let policy = Policy::compile(&[rule("ip", "10.0.0.0/8, 1.2.3.4", "direct")]);
        assert_eq!(
            policy
                .decide(&ctx("10.5.6.7", Some("10.5.6.7".parse().unwrap()), None))
                .map(|m| m.action),
            Some(RuleAction::Direct)
        );
        assert_eq!(
            policy.decide(&ctx("1.2.3.4", None, None)).map(|m| m.action),
            Some(RuleAction::Direct)
        );
        assert!(policy.decide(&ctx("8.8.8.8", None, None)).is_none());
    }

    #[test]
    fn process_exact_and_wildcard() {
        let policy = Policy::compile(&[rule("process", "chrome.exe", "proxy")]);
        assert!(policy.decide(&ctx("example.com", None, Some("chrome"))).is_some());
        assert!(policy
            .decide(&ctx("example.com", None, Some("C:\\Program Files\\Google\\Chrome\\chrome.exe")))
            .is_some());
        assert!(policy.decide(&ctx("example.com", None, Some("firefox"))).is_none());

        let policy = Policy::compile(&[rule("process", "steam*", "block")]);
        assert!(policy.decide(&ctx("x", None, Some("steamwebhelper"))).is_some());
        assert!(policy.decide(&ctx("x", None, Some("steam"))).is_some());
        assert!(policy.decide(&ctx("x", None, Some("epic"))).is_none());
    }

    #[test]
    fn first_match_wins_and_disabled_rules_are_skipped() {
        let mut first = rule("domain", "example.com", "direct");
        first.enabled = false;
        let policy = Policy::compile(&[
            first,
            rule("domain", "example.com", "block"),
            rule("all", "", "proxy"),
        ]);
        assert_eq!(
            policy.decide(&ctx("example.com", None, None)).map(|m| m.action),
            Some(RuleAction::Block)
        );
        assert_eq!(
            policy.decide(&ctx("other.net", None, None)).map(|m| m.action),
            Some(RuleAction::Proxy)
        );
    }

    #[test]
    fn domain_rules_ignore_raw_addresses() {
        let policy = Policy::compile(&[rule("domain", "8.8.8.8", "block")]);
        assert!(policy.decide(&ctx("8.8.8.8", None, None)).is_none());
    }

    #[test]
    fn glob_matcher() {
        assert!(glob_matches("*.example.com", "a.example.com"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "abbc"));
        assert!(glob_matches("*", "anything"));
    }

    #[cfg(all(windows, feature = "gui"))]
    #[test]
    fn locates_own_process_by_port() {
        // A listening socket is enough: the TCP table reports the owning PID
        // for listeners as well as for established connections.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let name = process_for_port(port).expect("own process must be visible in the TCP table");
        assert!(!name.is_empty());
    }
}
