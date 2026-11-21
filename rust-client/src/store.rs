//! Persistent configuration: subscriptions, derived profiles, settings.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::crypto::Keys;

pub const STORE_VERSION: u32 = 1;
pub const MANUAL_PROFILE_ID: &str = "manual";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub socks_listen: String,
    /// HTTP CONNECT proxy used by the Windows system proxy setting.
    pub http_listen: String,
    pub control_listen: String,
    pub poll_interval_ms: u64,
    pub poll_idle_ms: u64,
    pub poll_min_ms: u64,
    pub poll_jitter_ms: u64,
    pub max_chunk_bytes: usize,
    pub max_frames_per_poll: usize,
    pub pad_polls: bool,
    pub http2: bool,
    pub verify_tls: bool,
    pub poll_path: String,
    pub host_header: Option<String>,
    /// random | round
    pub selector: String,
    pub url_fail_limit: u32,
    pub url_cooldown_s: u64,
    /// Disabled entry URLs (same idea as Android's per-URL checkbox).
    pub disabled_urls: Vec<String>,
    pub idle_timeout_s: Option<u64>,
    /// Fallback PSK when the subscription has no per-user secret.
    pub psk: Option<String>,
    /// Manual mode: entry URLs used when the "manual" profile is active.
    pub server_urls: Vec<String>,
    pub dns_relay: Option<String>,
    pub check_url: String,
    /// Split-routing list overrides; empty means "use subscription values".
    pub geoip_url: Option<String>,
    pub domains_url: Option<String>,

    // Desktop UI state.
    /// `ru` or `en`.
    pub ui_language: String,
    pub ui_autostart: bool,
    pub ui_close_to_tray: bool,
    pub ui_start_minimized: bool,
    /// Automatically point the Windows system proxy at the local SOCKS5 port.
    pub system_proxy: bool,
    /// Mode used by the manual profile: `proxy` or `vpn`.
    pub manual_mode: String,

    // Native TUN (VPN) mode.
    pub tun_address: String,
    pub tun_netmask: String,
    pub tun_dns: String,
    pub tun_mtu: usize,
    /// DNS used by the built-in resolver (`ip:port`, UDP).
    pub tun_dns_upstream: String,
    /// Additional IPv4 destinations that must bypass the tunnel.
    pub tun_exclude: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            socks_listen: "127.0.0.1:8890".into(),
            http_listen: "127.0.0.1:18889".into(),
            control_listen: "127.0.0.1:8891".into(),
            poll_interval_ms: 200,
            poll_idle_ms: 800,
            poll_min_ms: 100,
            poll_jitter_ms: 5,
            max_chunk_bytes: 262144,
            max_frames_per_poll: 32,
            pad_polls: true,
            http2: true,
            verify_tls: true,
            poll_path: "/poll".into(),
            host_header: None,
            selector: "random".into(),
            url_fail_limit: 3,
            url_cooldown_s: 60,
            disabled_urls: Vec::new(),
            idle_timeout_s: None,
            psk: None,
            server_urls: Vec::new(),
            dns_relay: None,
            check_url: "https://www.cloudflare.com/cdn-cgi/trace".into(),
            geoip_url: None,
            domains_url: None,
            ui_language: "ru".into(),
            ui_autostart: false,
            ui_close_to_tray: true,
            ui_start_minimized: false,
            system_proxy: true,
            manual_mode: "proxy".into(),
            tun_address: "10.7.0.1".into(),
            tun_netmask: "255.255.255.0".into(),
            tun_dns: "10.7.0.53".into(),
            tun_mtu: 1400,
            tun_dns_upstream: "1.1.1.1:53".into(),
            tun_exclude: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub source: String,
    pub fetched_at: i64,
    pub raw: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub sub_id: String,
    pub name: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    /// `None` = inherit from subscription, `Some(true/false)` = override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_ru: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_non_ru: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_private: Option<String>,
}

fn default_mode() -> String {
    "proxy".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    pub device_id: String,
    pub active: Option<String>,
    pub settings: Settings,
    pub subscriptions: Vec<Subscription>,
    pub profiles: Vec<Profile>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            device_id: uuid::Uuid::new_v4().to_string(),
            active: None,
            settings: Settings::default(),
            subscriptions: Vec::new(),
            profiles: Vec::new(),
        }
    }
}

impl Store {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("config.json")
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        if !path.exists() {
            let store = Self::default();
            store.save(dir)?;
            return Ok(store);
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let mut store: Store = serde_json::from_str(&text)
            .with_context(|| format!("invalid JSON in {}", path.display()))?;
        if store.device_id.is_empty() {
            store.device_id = uuid::Uuid::new_v4().to_string();
        }
        if store.migrate_profile_routes() {
            let _ = store.save(dir);
        }
        Ok(store)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir);
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, text)?;
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn find_profile(&self, needle: &str) -> Option<&Profile> {
        let needle = needle.trim();
        self.profiles
            .iter()
            .find(|p| p.id == needle)
            .or_else(|| {
                let lower = needle.to_lowercase();
                self.profiles
                    .iter()
                    .find(|p| p.name.to_lowercase() == lower)
            })
    }

    pub fn active_profile(&self) -> Option<&Profile> {
        let id = self.active.as_deref()?;
        if id == MANUAL_PROFILE_ID {
            return None;
        }
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn has_manual(&self) -> bool {
        !self.settings.server_urls.is_empty()
    }

    /// Route names declared by the subscriptions, including legacy
    /// `profiles[].routes`, in subscription order and without duplicates.
    pub fn route_names(&self) -> Vec<String> {
        fn push_name(names: &mut Vec<String>, item: &Value) {
            if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                let name = name.trim();
                if !name.is_empty() && !names.iter().any(|known| known == name) {
                    names.push(name.to_owned());
                }
            }
        }
        let mut names: Vec<String> = Vec::new();
        for sub in &self.subscriptions {
            if let Some(routes) = sub.raw.get("routes").and_then(|v| v.as_array()) {
                for route in routes {
                    push_name(&mut names, route);
                }
            }
            if let Some(profiles) = sub.raw.get("profiles").and_then(|v| v.as_array()) {
                for profile in profiles {
                    if let Some(routes) = profile.get("routes").and_then(|v| v.as_array()) {
                        for route in routes {
                            push_name(&mut names, route);
                        }
                    }
                }
            }
        }
        names
    }

    /// Removes a subscription together with its derived profiles.
    pub fn remove_subscription(&mut self, needle: &str) -> bool {
        let before = self.subscriptions.len();
        let ids: Vec<String> = self
            .subscriptions
            .iter()
            .filter(|s| s.id == needle || s.source == needle)
            .map(|s| s.id.clone())
            .collect();
        self.subscriptions.retain(|s| !ids.contains(&s.id));
        self.profiles.retain(|p| !ids.contains(&p.sub_id));
        if let Some(active) = &self.active {
            if !self.profiles.iter().any(|p| &p.id == active) {
                self.active = self.profiles.first().map(|p| p.id.clone());
            }
        }
        self.subscriptions.len() != before
    }

    /// Older configs lost the per-profile routes from the subscription, so
    /// every profile silently fell back to the global non-RU route. Restore
    /// them from `client_profiles` without touching local overrides.
    fn migrate_profile_routes(&mut self) -> bool {
        let mut changed = false;
        for profile in &mut self.profiles {
            if profile.route_ru.is_some()
                && profile.route_non_ru.is_some()
                && profile.route_private.is_some()
            {
                continue;
            }
            let Some(sub) = self.subscriptions.iter().find(|s| s.id == profile.sub_id) else {
                continue;
            };
            let prefix = format!("{}::", sub.id);
            let Some(def_id) = profile.id.strip_prefix(&prefix) else {
                continue;
            };
            let Some(def) = client_profile_defs(&sub.raw)
                .into_iter()
                .find(|def| def.id == def_id)
            else {
                continue;
            };
            for (slot, value) in [
                (&mut profile.route_ru, def.route_ru),
                (&mut profile.route_non_ru, def.route_non_ru),
                (&mut profile.route_private, def.route_private),
            ] {
                if slot.is_none() && !value.is_empty() {
                    *slot = Some(value);
                    changed = true;
                }
            }
        }
        changed
    }

    /// Rebuilds profile rows from subscription `client_profiles`, keeping
    /// local routing overrides for profiles that still exist.
    pub fn sync_profiles(&mut self) {
        let existing: HashMap<String, Profile> = self
            .profiles
            .iter()
            .map(|p| (p.id.clone(), p.clone()))
            .collect();
        let mut profiles = Vec::new();
        for sub in &self.subscriptions {
            let defs = client_profile_defs(&sub.raw);
            if defs.is_empty() {
                let id = format!("{}::default", sub.id);
                let old = existing.get(&id);
                profiles.push(Profile {
                    id,
                    sub_id: sub.id.clone(),
                    name: "Default".into(),
                    mode: "proxy".into(),
                    split: old.and_then(|p| p.split),
                    route_ru: old.and_then(|p| p.route_ru.clone()),
                    route_non_ru: old.and_then(|p| p.route_non_ru.clone()),
                    route_private: old.and_then(|p| p.route_private.clone()),
                });
                continue;
            }
            for def in defs {
                if !def.enabled {
                    continue;
                }
                let id = format!("{}::{}", sub.id, def.id);
                let old = existing.get(&id);
                let route_ru = (!def.route_ru.is_empty()).then_some(def.route_ru);
                let route_non_ru = (!def.route_non_ru.is_empty()).then_some(def.route_non_ru);
                let route_private = (!def.route_private.is_empty()).then_some(def.route_private);
                profiles.push(Profile {
                    id,
                    sub_id: sub.id.clone(),
                    name: def.name,
                    mode: def.mode,
                    split: old.and_then(|p| p.split),
                    route_ru: old.and_then(|p| p.route_ru.clone()).or(route_ru),
                    route_non_ru: old.and_then(|p| p.route_non_ru.clone()).or(route_non_ru),
                    route_private: old.and_then(|p| p.route_private.clone()).or(route_private),
                });
            }
        }
        self.profiles = profiles;
        if let Some(active) = &self.active {
            if !self.profiles.iter().any(|p| &p.id == active) {
                self.active = None;
            }
        }
        if self.active.is_none() {
            self.active = self.profiles.first().map(|p| p.id.clone());
        }
    }

    /// Resolves the runtime configuration for a profile (or the active one).
    pub fn resolve(&self, profile: Option<&Profile>) -> Result<ResolvedProfile> {
        if let Some(profile) = profile {
            if let Some(sub) = self.subscriptions.iter().find(|s| s.id == profile.sub_id) {
                return ResolvedProfile::from_subscription(self, sub, Some(profile));
            }
            bail!("subscription {} not found for profile {}", profile.sub_id, profile.name);
        }
        if !self.settings.server_urls.is_empty() {
            return ResolvedProfile::manual(self);
        }
        if let Some(profile) = self.active_profile() {
            return self.resolve(Some(profile));
        }
        bail!("no active profile: add a subscription first (`spvpn subs add <url>`)");
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Node {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub region: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Hop {
    #[serde(default)]
    pub candidates: Vec<String>,
    #[serde(default)]
    pub strategy: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RouteDef {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub hops: Vec<Hop>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Action {
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub route: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SplitRules {
    #[serde(alias = "geoip_url")]
    pub geoip: String,
    #[serde(alias = "domains_url")]
    pub domains: String,
    pub ru_domains: Vec<String>,
    pub direct_domains: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SplitConfig {
    pub enabled: bool,
    pub default: String,
    pub rules: SplitRules,
    pub actions: HashMap<String, Action>,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default: "non_ru".into(),
            rules: SplitRules::default(),
            actions: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UserDef {
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientProfileDef {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub route_ru: String,
    #[serde(default)]
    pub route_non_ru: String,
    #[serde(default)]
    pub route_private: String,
}

fn default_true() -> bool {
    true
}

pub fn client_profile_defs(raw: &Value) -> Vec<ClientProfileDef> {
    let Some(arr) = raw.get("client_profiles").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let mut def: ClientProfileDef =
            serde_json::from_value(item.clone()).unwrap_or(ClientProfileDef {
                id: String::new(),
                name: String::new(),
                mode: "proxy".into(),
                enabled: true,
                route_ru: String::new(),
                route_non_ru: String::new(),
                route_private: String::new(),
            });
        if def.id.is_empty() {
            def.id = format!("p{i}");
        }
        if def.name.is_empty() {
            def.name = format!("Profile {}", i + 1);
        }
        out.push(def);
    }
    out
}

pub fn subscription_name(raw: &Value, source: &str) -> String {
    if let Some(name) = raw
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        return name.to_owned();
    }
    if let Some(user) = raw.get("user").and_then(|u| u.get("name")).and_then(|v| v.as_str()) {
        if !user.trim().is_empty() {
            return user.to_owned();
        }
    }
    if let Ok(url) = url::Url::parse(source) {
        if let Some(host) = url.host_str() {
            return host.to_owned();
        }
    }
    "Subscription".into()
}

/// Everything the tunnel/router needs, decoupled from the on-disk store.
#[derive(Clone)]
pub struct ResolvedProfile {
    pub name: String,
    /// `proxy` or `vpn`.
    pub mode: String,
    pub settings: Settings,
    pub keys: Keys,
    pub user_id: Option<String>,
    pub device_id: String,
    pub urls: Vec<String>,
    pub nodes: Vec<Node>,
    pub routes: Vec<RouteDef>,
    pub split: SplitConfig,
}

impl ResolvedProfile {
    fn base(store: &Store, name: String, settings: Settings) -> Self {
        Self {
            name,
            mode: "proxy".into(),
            settings,
            // Replaced below once the key source is known.
            keys: Keys::from_psk_b64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .expect("valid placeholder"),
            user_id: None,
            device_id: store.device_id.clone(),
            urls: Vec::new(),
            nodes: Vec::new(),
            routes: Vec::new(),
            split: SplitConfig::default(),
        }
    }

    pub fn manual(store: &Store) -> Result<Self> {
        let settings = store.settings.clone();
        let psk = settings
            .psk
            .clone()
            .context("manual mode requires a PSK: spvpn config set psk <base64>")?;
        let mut resolved = Self::base(store, "Manual".into(), settings);
        resolved.mode = if store.settings.manual_mode.eq_ignore_ascii_case("vpn") {
            "vpn".into()
        } else {
            "proxy".into()
        };
        resolved.keys = Keys::from_psk_b64(&psk)?;
        resolved.urls = dedup_urls(&resolved.settings.server_urls);
        resolved.nodes = resolved
            .urls
            .iter()
            .enumerate()
            .map(|(i, url)| Node {
                id: format!("node-{}", i + 1),
                name: format!("node-{}", i + 1),
                url: url.clone(),
                region: String::new(),
            })
            .collect();
        resolved.split.enabled = false;
        Ok(resolved)
    }

    pub fn from_subscription(store: &Store, sub: &Subscription, profile: Option<&Profile>) -> Result<Self> {
        let mut settings = store.settings.clone();
        let mut nodes: Vec<Node> = serde_json::from_value(
            sub.raw
                .get("nodes")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        )
        .unwrap_or_default();
        let routes: Vec<RouteDef> = serde_json::from_value(
            sub.raw
                .get("routes")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        )
        .unwrap_or_default();
        let mut split: SplitConfig = serde_json::from_value(
            sub.raw
                .get("split_routing")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .unwrap_or_default();
        if split.rules.geoip.is_empty() {
            if let Some(url) = settings.geoip_url.take() {
                split.rules.geoip = url;
            }
        }
        if split.rules.domains.is_empty() {
            if let Some(url) = settings.domains_url.take() {
                split.rules.domains = url;
            }
        }

        // Legacy routing definitions live inside subscription profiles[].routes.
        let mut all_routes = routes;
        if let Some(profiles) = sub.raw.get("profiles").and_then(|v| v.as_array()) {
            for p in profiles {
                if let Some(rs) = p.get("routes").and_then(|v| v.as_array()) {
                    for r in rs {
                        if let Ok(def) = serde_json::from_value::<RouteDef>(r.clone()) {
                            if !all_routes.iter().any(|x| x.name == def.name) {
                                all_routes.push(def);
                            }
                        }
                    }
                }
            }
        }

        let name = profile
            .map(|p| p.name.clone())
            .unwrap_or_else(|| subscription_name(&sub.raw, &sub.source));
        let mut resolved = Self::base(store, name, settings.clone());
        if let Some(profile) = profile {
            resolved.mode = if profile.mode.eq_ignore_ascii_case("vpn") {
                "vpn".into()
            } else {
                "proxy".into()
            };
        }

        // Per-user auth from the subscription.
        if let Ok(user) = serde_json::from_value::<UserDef>(
            sub.raw.get("user").cloned().unwrap_or(Value::Null),
        ) {
            if !user.uuid.is_empty() && !user.secret.is_empty() {
                resolved.keys = Keys::from_user_secret(&user.secret)?;
                resolved.user_id = Some(user.uuid);
            }
        }
        if resolved.user_id.is_none() {
            let psk = settings
                .psk
                .as_deref()
                .context("subscription has no per-user secret and settings.psk is empty")?;
            resolved.keys = Keys::from_psk_b64(psk)?;
        }

        // A disabled node must also disappear from route candidates: otherwise
        // a route that names it keeps selecting a node the user turned off.
        let disabled: HashSet<String> = settings
            .disabled_urls
            .iter()
            .map(|url| url.trim_end_matches('/').to_owned())
            .collect();
        nodes.retain(|node| !disabled.contains(node.url.trim_end_matches('/')));
        resolved.urls = dedup_urls(&nodes.iter().map(|n| n.url.clone()).collect::<Vec<_>>());
        resolved.nodes = nodes;
        resolved.routes = all_routes;
        resolved.split = split;

        if let Some(profile) = profile {
            if let Some(enabled) = profile.split {
                resolved.split.enabled = enabled;
            }
            apply_action(&mut resolved.split, "ru", profile.route_ru.as_deref());
            apply_action(&mut resolved.split, "non_ru", profile.route_non_ru.as_deref());
            apply_action(&mut resolved.split, "private", profile.route_private.as_deref());
        }

        if resolved.urls.is_empty() {
            bail!("subscription {} has no usable nodes", sub.name);
        }
        Ok(resolved)
    }

    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }
}

fn apply_action(split: &mut SplitConfig, category: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    if value.eq_ignore_ascii_case("inherit") {
        return;
    }
    let action = if value.eq_ignore_ascii_case("direct") {
        Action {
            direct: true,
            route: None,
        }
    } else {
        Action {
            direct: false,
            route: Some(value.to_owned()),
        }
    };
    split.actions.insert(category.to_owned(), action);
}

fn dedup_urls(urls: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    urls.iter()
        .map(|u| u.trim().trim_end_matches('/').to_owned())
        .filter(|u| !u.is_empty())
        .filter(|u| seen.insert(u.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_subscription() -> Value {
        serde_json::json!({
            "user": {"uuid": "e8d8fafd-b46a-4480-8135-f35ddd72baec",
                      "secret": "26bfk_i5wgc22diXHqNEGPF0BrmmlR0RTLho8ErjIcg"},
            "nodes": [
                {"id": "ru", "name": "RU", "url": "https://ru.example"},
                {"id": "de", "name": "DE", "url": "https://de.example/"}
            ],
            "routes": [
                {"name": "RU exit", "hops": [{"candidates": ["ru"]}]},
                {"name": "DE fallback", "hops": [{"candidates": ["ru"]}, {"candidates": ["de"]}]}
            ],
            "client_profiles": [
                {"id": "a", "name": "Split", "mode": "vpn", "enabled": true},
                {"id": "b", "name": "Off", "mode": "proxy", "enabled": false}
            ],
            "split_routing": {
                "enabled": true, "default": "non_ru",
                "actions": {"non_ru": {"route": "DE fallback"}, "private": {"direct": true}}
            }
        })
    }

    #[test]
    fn syncs_only_enabled_profiles() {
        let mut store = Store::default();
        store.subscriptions.push(Subscription {
            id: "s1".into(),
            name: "test".into(),
            source: "https://example/sub".into(),
            fetched_at: 0,
            raw: sample_subscription(),
        });
        store.sync_profiles();
        assert_eq!(store.profiles.len(), 1);
        assert_eq!(store.profiles[0].name, "Split");
        assert_eq!(store.active.as_deref(), Some(store.profiles[0].id.as_str()));
    }

    #[test]
    fn subscription_routes_seed_profiles() {
        let mut raw = sample_subscription();
        raw["client_profiles"][0]["route_ru"] = serde_json::json!("RU exit");
        raw["client_profiles"][0]["route_non_ru"] = serde_json::json!("DE fallback");
        let mut store = Store::default();
        store.subscriptions.push(Subscription {
            id: "s1".into(),
            name: "test".into(),
            source: "x".into(),
            fetched_at: 0,
            raw,
        });
        store.sync_profiles();
        assert_eq!(store.profiles[0].route_ru.as_deref(), Some("RU exit"));
        assert_eq!(store.profiles[0].route_non_ru.as_deref(), Some("DE fallback"));
    }

    #[test]
    fn migration_restores_routes_for_existing_config() {
        let mut raw = sample_subscription();
        raw["client_profiles"][0]["route_non_ru"] = serde_json::json!("DE fallback");
        let mut store = Store::default();
        store.subscriptions.push(Subscription {
            id: "s1".into(),
            name: "test".into(),
            source: "x".into(),
            fetched_at: 0,
            raw,
        });
        store.profiles.push(Profile {
            id: "s1::a".into(),
            sub_id: "s1".into(),
            name: "Split".into(),
            mode: "vpn".into(),
            split: None,
            route_ru: None,
            route_non_ru: None,
            route_private: None,
        });
        assert!(store.migrate_profile_routes());
        assert_eq!(store.profiles[0].route_non_ru.as_deref(), Some("DE fallback"));
    }

    #[test]
    fn routing_override_wins() {
        let mut store = Store::default();
        store.subscriptions.push(Subscription {
            id: "s1".into(),
            name: "test".into(),
            source: "x".into(),
            fetched_at: 0,
            raw: sample_subscription(),
        });
        store.sync_profiles();
        store.profiles[0].route_non_ru = Some("RU exit".into());
        store.profiles[0].route_private = Some("direct".into());
        let resolved = store.resolve(Some(&store.profiles[0])).unwrap();
        assert_eq!(resolved.split.actions["non_ru"].route.as_deref(), Some("RU exit"));
        assert!(resolved.split.actions["private"].direct);
        assert_eq!(resolved.urls.len(), 2);
        assert_eq!(resolved.urls[1], "https://de.example");
    }

    #[test]
    fn profile_overrides_survive_refresh() {
        let mut store = Store::default();
        store.subscriptions.push(Subscription {
            id: "s1".into(),
            name: "test".into(),
            source: "x".into(),
            fetched_at: 0,
            raw: sample_subscription(),
        });
        store.sync_profiles();
        let id = store.profiles[0].id.clone();
        store.profiles[0].route_ru = Some("direct".into());
        store.sync_profiles();
        assert_eq!(store.profiles[0].id, id);
        assert_eq!(store.profiles[0].route_ru.as_deref(), Some("direct"));
    }
}
