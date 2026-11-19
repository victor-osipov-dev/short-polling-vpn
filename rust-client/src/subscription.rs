//! Subscription import/refresh. A subscription is a JSON object served by the
//! admin panel (`/sub/<token>`), or a local file / inline JSON.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::Path;

use crate::store::{client_profile_defs, subscription_name, Store, Subscription};

pub async fn fetch(source: &str, client: &reqwest::Client) -> Result<Value> {
    let source = source.trim();
    if source.is_empty() {
        bail!("empty subscription source");
    }
    let text = if source.starts_with('{') {
        source.to_owned()
    } else if source.starts_with("http://") || source.starts_with("https://") {
        let resp = client
            .get(source)
            .header(reqwest::header::USER_AGENT, "vpn-client/1.0")
            .send()
            .await
            .with_context(|| format!("cannot fetch subscription {source}"))?;
        if !resp.status().is_success() {
            bail!("subscription {source}: HTTP {}", resp.status());
        }
        resp.text().await.context("cannot read subscription body")?
    } else {
        let path = Path::new(source);
        std::fs::read_to_string(path)
            .with_context(|| format!("cannot read subscription file {}", path.display()))?
    };
    let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .context("subscription is not valid JSON")?;
    if !value.is_object() {
        bail!("subscription must be a JSON object");
    }
    Ok(value)
}

pub async fn add(
    store: &mut Store,
    source: &str,
    name: Option<String>,
    client: &reqwest::Client,
) -> Result<String> {
    let raw = fetch(source, client).await?;
    let now = now_secs();
    let id = if let Some(existing) = store.subscriptions.iter_mut().find(|s| s.source == source) {
        existing.raw = raw.clone();
        existing.fetched_at = now;
        if let Some(name) = name.filter(|n| !n.trim().is_empty()) {
            existing.name = name;
        }
        existing.id.clone()
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        let name = name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| subscription_name(&raw, source));
        store.subscriptions.push(Subscription {
            id: id.clone(),
            name,
            source: source.to_owned(),
            fetched_at: now,
            raw,
        });
        id
    };
    store.sync_profiles();
    if store.active.is_none() {
        store.active = store
            .profiles
            .iter()
            .find(|p| p.sub_id == id)
            .map(|p| p.id.clone());
    }
    Ok(id)
}

pub async fn refresh(store: &mut Store, needle: Option<&str>, client: &reqwest::Client) -> Result<usize> {
    let mut updated = 0;
    let ids: Vec<String> = store
        .subscriptions
        .iter()
        .filter(|s| needle.map(|n| s.id == n || s.source == n).unwrap_or(true))
        .map(|s| s.id.clone())
        .collect();
    if ids.is_empty() {
        bail!("no matching subscriptions");
    }
    let mut errors = Vec::new();
    for id in ids {
        let Some(sub) = store.subscriptions.iter_mut().find(|s| s.id == id) else {
            continue;
        };
        match fetch(&sub.source, client).await {
            Ok(raw) => {
                let defs = client_profile_defs(&raw).len();
                sub.raw = raw;
                sub.fetched_at = now_secs();
                updated += 1;
                tracing::info!("subscription {:?} refreshed ({} profiles)", sub.name, defs);
            }
            Err(err) => {
                errors.push(format!("{}: {err}", sub.name));
                tracing::warn!("subscription refresh failed: {err}");
            }
        }
    }
    store.sync_profiles();
    if updated == 0 && !errors.is_empty() {
        bail!("{}", errors.join("; "));
    }
    Ok(updated)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
