//! Split routing and relay-chain construction (mirrors split_routing.py).

use anyhow::Result;
use ipnet::IpNet;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::store::{Hop, Node, RouteDef, SplitConfig};

pub const MAX_HOPS: usize = 3;

const DEFAULT_PRIVATE: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];
const DEFAULT_DIRECT_DOMAINS: &[&str] = &["localhost", "local", "lan", "home.arpa"];
const DEFAULT_RU_SUFFIXES: &[&str] = &[
    "ru", "xn--p1ai", "su", "vk.com", "yandex.com", "yandex.net", "2gis.com",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Ru,
    NonRu,
    Private,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Ru => "ru",
            Category::NonRu => "non_ru",
            Category::Private => "private",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Ruleset {
    pub ru_nets: Vec<IpNet>,
    pub private_nets: Vec<IpNet>,
    pub ru_domains: Vec<String>,
    pub direct_domains: Vec<String>,
}

impl Ruleset {
    pub fn load(cache_dir: &Path, split: &SplitConfig) -> Self {
        let mut ru_nets = Vec::new();
        let mut ru_domains: Vec<String> = DEFAULT_RU_SUFFIXES.iter().map(|s| s.to_string()).collect();
        let mut direct_domains: Vec<String> =
            DEFAULT_DIRECT_DOMAINS.iter().map(|s| s.to_string()).collect();

        if let Some(path) = cache_path(cache_dir, &split.rules.geoip) {
            if let Ok(text) = std::fs::read_to_string(path) {
                ru_nets = parse_cidrs(&text);
            }
        }
        if let Some(path) = cache_path(cache_dir, &split.rules.domains) {
            if let Ok(text) = std::fs::read_to_string(path) {
                ru_domains.extend(parse_domains(&text));
            }
        }
        ru_domains.extend(split.rules.ru_domains.iter().map(|d| d.to_lowercase()));
        direct_domains.extend(
            split
                .rules
                .direct_domains
                .iter()
                .map(|d| d.to_lowercase()),
        );

        let mut private_nets: Vec<IpNet> = DEFAULT_PRIVATE
            .iter()
            .filter_map(|c| c.parse::<IpNet>().ok())
            .collect();
        private_nets.extend(ru_nets.iter().copied().filter(|_| false));

        Self {
            ru_nets,
            private_nets,
            ru_domains: dedup(ru_domains),
            direct_domains: dedup(direct_domains),
        }
    }

    fn matches_domain(host: &str, domains: &[String]) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    pub fn classify(&self, host: &str) -> Category {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        if host.is_empty() {
            return Category::NonRu;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self
                .private_nets
                .iter()
                .any(|net| net.contains(&ip) && net.addr().is_ipv4() == ip.is_ipv4())
            {
                return Category::Private;
            }
            if self
                .ru_nets
                .iter()
                .any(|net| net.contains(&ip) && net.addr().is_ipv4() == ip.is_ipv4())
            {
                return Category::Ru;
            }
            return Category::NonRu;
        }
        if Self::matches_domain(&host, &self.direct_domains) {
            return Category::Private;
        }
        if Self::matches_domain(&host, &self.ru_domains) {
            return Category::Ru;
        }
        Category::NonRu
    }
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .map(|s| s.trim().trim_start_matches('.').to_lowercase())
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

pub fn parse_domains(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim().to_lowercase();
        if line.is_empty() {
            continue;
        }
        for part in line.replace(',', " ").split_whitespace() {
            let part = part.trim_start_matches("*.").trim_start_matches('.');
            if !part.is_empty() && !part.starts_with('!') {
                out.push(part.to_owned());
            }
        }
    }
    out
}

pub fn parse_cidrs(text: &str) -> Vec<IpNet> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            line.split_whitespace()
                .next()
                .and_then(|token| token.parse::<IpNet>().ok())
        })
        .collect()
}

pub fn cache_path(cache_dir: &Path, source: &str) -> Option<PathBuf> {
    if source.is_empty() {
        return None;
    }
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in source.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Some(cache_dir.join(format!("rules-{hash:016x}.txt")))
}

/// Downloads rule lists into the cache when missing or older than a day.
pub async fn refresh_rules(
    cache_dir: &Path,
    split: &SplitConfig,
    client: &reqwest::Client,
) -> Result<usize> {
    std::fs::create_dir_all(cache_dir)?;
    let mut updated = 0;
    for source in [&split.rules.geoip, &split.rules.domains] {
        if source.is_empty() {
            continue;
        }
        let Some(path) = cache_path(cache_dir, source) else {
            continue;
        };
        let fresh = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| {
                SystemTime::now()
                    .duration_since(t)
                    .unwrap_or(Duration::ZERO)
                    < Duration::from_secs(24 * 3600)
            })
            .unwrap_or(false);
        if fresh {
            continue;
        }
        match client.get(source).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.text().await {
                    std::fs::write(&path, body)?;
                    updated += 1;
                }
            }
            Ok(resp) => tracing::warn!("rules {}: HTTP {}", source, resp.status()),
            Err(err) => tracing::warn!("rules {}: {}", source, err),
        }
    }
    Ok(updated)
}

#[derive(Clone, Debug)]
pub enum Decision {
    Direct,
    Tunnel {
        entry: String,
        chain: Vec<String>,
        category: Category,
    },
    Error(String),
}

pub struct Router {
    pub split: SplitConfig,
    pub ruleset: Ruleset,
    pub nodes: Vec<Node>,
    node_urls: HashMap<String, String>,
    url_nodes: HashMap<String, String>,
    fallback_urls: Vec<String>,
    routes: HashMap<String, Vec<Hop>>,
    selector: String,
    rr: Mutex<HashMap<String, usize>>,
    global_rr: Mutex<usize>,
}

impl Router {
    pub fn new(
        split: SplitConfig,
        ruleset: Ruleset,
        nodes: Vec<Node>,
        routes: Vec<RouteDef>,
        fallback_urls: Vec<String>,
        selector: &str,
    ) -> Self {
        let mut node_urls = HashMap::new();
        let mut url_nodes = HashMap::new();
        for node in &nodes {
            let url = node.url.trim_end_matches('/').to_owned();
            if !node.id.is_empty() && !url.is_empty() {
                node_urls.insert(node.id.clone(), url.clone());
                url_nodes.entry(url).or_insert_with(|| node.id.clone());
            }
        }
        let mut route_map = HashMap::new();
        for route in routes {
            route_map.entry(route.name).or_insert(route.hops);
        }
        Self {
            split,
            ruleset,
            nodes,
            node_urls,
            url_nodes,
            fallback_urls,
            routes: route_map,
            selector: selector.to_lowercase(),
            rr: Mutex::new(HashMap::new()),
            global_rr: Mutex::new(0),
        }
    }

    pub fn route_for(&self, host: &str, available: &HashSet<String>) -> Decision {
        if !self.split.enabled {
            return match self.pick_any(available, "global") {
                Some(entry) => Decision::Tunnel {
                    entry,
                    chain: Vec::new(),
                    category: Category::NonRu,
                },
                None => Decision::Error("no reachable entry URL".into()),
            };
        }
        let category = self.ruleset.classify(host);
        let action = self
            .split
            .actions
            .get(category.as_str())
            .or_else(|| self.split.actions.get(&self.split.default));
        let Some(action) = action else {
            return match self.pick_any(available, "global") {
                Some(entry) => Decision::Tunnel {
                    entry,
                    chain: Vec::new(),
                    category,
                },
                None => Decision::Error("no reachable entry URL".into()),
            };
        };
        if action.direct {
            return Decision::Direct;
        }
        let Some(route_name) = action.route.as_deref() else {
            return match self.pick_any(available, "global") {
                Some(entry) => Decision::Tunnel {
                    entry,
                    chain: Vec::new(),
                    category,
                },
                None => Decision::Error("no reachable entry URL".into()),
            };
        };
        match self.build_chain(route_name, available) {
            Some(hops) if !hops.is_empty() => {
                let entry = hops[0].1.clone();
                if hops.len() == 1 {
                    Decision::Tunnel {
                        entry,
                        chain: Vec::new(),
                        category,
                    }
                } else if hops.iter().any(|(id, _)| id.is_empty()) {
                    Decision::Tunnel {
                        entry: hops.last().expect("non-empty").1.clone(),
                        chain: Vec::new(),
                        category,
                    }
                } else {
                    Decision::Tunnel {
                        entry,
                        chain: hops.into_iter().map(|(id, _)| id).collect(),
                        category,
                    }
                }
            }
            _ => Decision::Error(format!(
                "route {route_name:?} cannot be built (not enough distinct nodes)"
            )),
        }
    }

    fn pick_any(&self, available: &HashSet<String>, key: &str) -> Option<String> {
        let pool: Vec<&String> = self
            .fallback_urls
            .iter()
            .filter(|u| available.contains(u.as_str()))
            .collect();
        let pool = if pool.is_empty() {
            self.fallback_urls.iter().collect::<Vec<_>>()
        } else {
            pool
        };
        if pool.is_empty() {
            return None;
        }
        if self.selector == "random" || pool.len() == 1 {
            return pool.choose(&mut rand::thread_rng()).map(|u| (*u).clone());
        }
        let mut rr = self.global_rr.lock();
        let idx = *rr % pool.len();
        *rr = rr.wrapping_add(1);
        let _ = key;
        Some(pool[idx].clone())
    }

    fn build_chain(&self, route_name: &str, available: &HashSet<String>) -> Option<Vec<(String, String)>> {
        let hops = self.routes.get(route_name)?;
        if hops.is_empty() {
            return None;
        }
        let hops = &hops[..hops.len().min(MAX_HOPS)];
        let mut pools: Vec<Vec<(String, String)>> = Vec::with_capacity(hops.len());
        let mut strategies = Vec::with_capacity(hops.len());
        for (i, hop) in hops.iter().enumerate() {
            let mut candidates = Vec::new();
            let mut seen = HashSet::new();
            for raw in &hop.candidates {
                let cand = raw.trim();
                if cand.is_empty() {
                    continue;
                }
                let (node_id, url) = if cand.starts_with("http://") || cand.starts_with("https://") {
                    let url = cand.trim_end_matches('/').to_owned();
                    (self.url_nodes.get(&url).cloned().unwrap_or_default(), url)
                } else {
                    (
                        cand.to_owned(),
                        self.node_urls.get(cand).cloned().unwrap_or_default(),
                    )
                };
                if url.is_empty() {
                    tracing::warn!("route {:?} hop {}: {:?} has no URL", route_name, i + 1, cand);
                    continue;
                }
                let key = if node_id.is_empty() {
                    url.clone()
                } else {
                    node_id.clone()
                };
                if seen.insert(key) {
                    candidates.push((node_id, url));
                }
            }
            if candidates.is_empty() {
                candidates = self
                    .fallback_urls
                    .iter()
                    .map(|u| (self.url_nodes.get(u).cloned().unwrap_or_default(), u.clone()))
                    .collect();
            }
            if candidates.is_empty() {
                return None;
            }
            pools.push(candidates);
            strategies.push(
                hop.strategy
                    .as_deref()
                    .unwrap_or("round")
                    .to_lowercase(),
            );
        }

        // Prefer nodes that are currently not quarantined, but never fail just
        // because all of them are: the chain may still work.
        let filtered: Vec<Vec<(String, String)>> = pools
            .iter()
            .map(|pool| {
                let usable: Vec<_> = pool
                    .iter()
                    .filter(|(_, url)| available.is_empty() || available.contains(url))
                    .cloned()
                    .collect();
                if usable.is_empty() {
                    pool.clone()
                } else {
                    usable
                }
            })
            .collect();

        let requested = filtered.len();
        for length in (1..=requested).rev() {
            let mut picked = Vec::new();
            if search_chain(
                &filtered[..length],
                &strategies[..length],
                &self.rr,
                route_name,
                0,
                &mut HashSet::new(),
                &mut HashSet::new(),
                &mut picked,
            ) {
                // Advance round-robin counters for the hops we actually used.
                for i in 0..length {
                    if strategies[i] != "random" && !filtered[i].is_empty() {
                        let mut rr = self.rr.lock();
                        let key = format!("{route_name}:{i}");
                        let cur = rr.entry(key).or_insert(0);
                        *cur = (*cur + 1) % filtered[i].len();
                    }
                }
                if length < requested {
                    tracing::warn!(
                        "route {:?}: using {} hop(s) instead of {} (not enough distinct nodes)",
                        route_name,
                        length,
                        requested
                    );
                }
                return Some(picked);
            }
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn search_chain(
    pools: &[Vec<(String, String)>],
    strategies: &[String],
    rr: &Mutex<HashMap<String, usize>>,
    route_name: &str,
    depth: usize,
    used_ids: &mut HashSet<String>,
    used_urls: &mut HashSet<String>,
    picked: &mut Vec<(String, String)>,
) -> bool {
    if depth == pools.len() {
        return true;
    }
    let pool = &pools[depth];
    let mut order: Vec<usize> = (0..pool.len()).collect();
    if strategies[depth] == "random" {
        order.shuffle(&mut rand::thread_rng());
    } else {
        let start = *rr.lock().get(&format!("{route_name}:{depth}")).unwrap_or(&0) % pool.len();
        order = (0..pool.len()).map(|k| (start + k) % pool.len()).collect();
    }
    for pos in order {
        let (id, url) = &pool[pos];
        let key = if id.is_empty() { url.clone() } else { id.clone() };
        if used_ids.contains(&key) || (!url.is_empty() && used_urls.contains(url)) {
            continue;
        }
        used_ids.insert(key.clone());
        if !url.is_empty() {
            used_urls.insert(url.clone());
        }
        picked.push((id.clone(), url.clone()));
        if search_chain(
            pools, strategies, rr, route_name, depth + 1, used_ids, used_urls, picked,
        ) {
            return true;
        }
        picked.pop();
        used_ids.remove(&key);
        if !url.is_empty() {
            used_urls.remove(url);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Action;

    fn split(actions: &[(&str, &str)]) -> SplitConfig {
        let mut cfg = SplitConfig {
            enabled: true,
            ..Default::default()
        };
        for (cat, route) in actions {
            cfg.actions.insert(
                (*cat).to_owned(),
                Action {
                    direct: false,
                    route: Some((*route).to_owned()),
                },
            );
        }
        cfg
    }

    fn nodes() -> Vec<Node> {
        ["ru", "de", "fi", "jp"]
            .iter()
            .map(|id| Node {
                id: (*id).to_owned(),
                name: (*id).to_owned(),
                url: format!("https://{id}.example"),
                region: String::new(),
            })
            .collect()
    }

    fn routes() -> Vec<RouteDef> {
        vec![
            RouteDef {
                id: "1".into(),
                name: "DE".into(),
                hops: vec![Hop {
                    candidates: vec!["de".into()],
                    strategy: Some("round".into()),
                }],
            },
            RouteDef {
                id: "2".into(),
                name: "mask".into(),
                hops: vec![
                    Hop {
                        candidates: vec!["ru".into(), "fi".into()],
                        strategy: None,
                    },
                    Hop {
                        candidates: vec!["de".into(), "jp".into()],
                        strategy: None,
                    },
                ],
            },
            RouteDef {
                id: "3".into(),
                name: "impossible".into(),
                hops: vec![
                    Hop {
                        candidates: vec!["de".into()],
                        strategy: None,
                    },
                    Hop {
                        candidates: vec!["de".into()],
                        strategy: None,
                    },
                ],
            },
        ]
    }

    #[test]
    fn classifies_like_python() {
        let rules = Ruleset::load(Path::new("__missing__"), &SplitConfig::default());
        assert_eq!(rules.classify("ya.ru"), Category::Ru);
        assert_eq!(rules.classify("sub.ya.ru."), Category::Ru);
        assert_eq!(rules.classify("example.com"), Category::NonRu);
        assert_eq!(rules.classify("192.168.1.1"), Category::Private);
        assert_eq!(rules.classify("8.8.8.8"), Category::NonRu);
    }

    #[test]
    fn parses_lists() {
        assert_eq!(
            parse_domains("# c\n*.foo.ru, bar.su\n!baz\n"),
            vec!["foo.ru", "bar.su"]
        );
        assert_eq!(parse_cidrs("5.8.0.0/16 x\nbad\n").len(), 1);
    }

    #[test]
    fn builds_relay_chain_without_repeats() {
        let split = split(&[("non_ru", "mask")]);
        let urls: Vec<String> = nodes().iter().map(|n| n.url.clone()).collect();
        let router = Router::new(
            split,
            Ruleset::load(Path::new("__missing__"), &SplitConfig::default()),
            nodes(),
            routes(),
            urls.clone(),
            "round",
        );
        let available: HashSet<String> = urls.into_iter().collect();
        match router.route_for("example.com", &available) {
            Decision::Tunnel { entry, chain, .. } => {
                assert_eq!(chain.len(), 2);
                assert_ne!(chain[0], chain[1]);
                assert!(entry.contains(&chain[0]));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn duplicate_nodes_shorten_the_chain() {
        let split = split(&[("non_ru", "impossible")]);
        let urls: Vec<String> = nodes().iter().map(|n| n.url.clone()).collect();
        let router = Router::new(
            split,
            Ruleset::load(Path::new("__missing__"), &SplitConfig::default()),
            nodes(),
            routes(),
            urls.clone(),
            "round",
        );
        let available: HashSet<String> = urls.into_iter().collect();
        // Two hops cannot use the same node twice, so the client falls back to
        // the longest valid prefix (one hop) instead of failing the route.
        match router.route_for("example.com", &available) {
            Decision::Tunnel { chain, .. } => assert!(chain.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn missing_route_is_an_error() {
        let split = split(&[("non_ru", "does-not-exist")]);
        let urls: Vec<String> = nodes().iter().map(|n| n.url.clone()).collect();
        let router = Router::new(
            split,
            Ruleset::load(Path::new("__missing__"), &SplitConfig::default()),
            nodes(),
            routes(),
            urls.clone(),
            "round",
        );
        let available: HashSet<String> = urls.into_iter().collect();
        assert!(matches!(
            router.route_for("example.com", &available),
            Decision::Error(_)
        ));
    }

    #[test]
    fn direct_action_wins() {
        let mut split = split(&[]);
        split.actions.insert(
            "private".into(),
            Action {
                direct: true,
                route: None,
            },
        );
        let urls: Vec<String> = nodes().iter().map(|n| n.url.clone()).collect();
        let router = Router::new(
            split,
            Ruleset::load(Path::new("__missing__"), &SplitConfig::default()),
            nodes(),
            routes(),
            urls.clone(),
            "random",
        );
        let available: HashSet<String> = urls.into_iter().collect();
        assert!(matches!(
            router.route_for("192.168.0.1", &available),
            Decision::Direct
        ));
    }
}
