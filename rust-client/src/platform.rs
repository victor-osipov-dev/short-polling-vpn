//! Windows integration: system proxy, autostart and UAC helpers.

#![cfg(windows)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "SPVPN";

#[derive(Serialize, Deserialize, Default)]
struct ProxyBackup {
    enabled: Option<u32>,
    server: Option<String>,
    bypass: Option<String>,
}

fn settings_key(write: bool) -> Result<RegKey> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let flags = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
    hkcu.open_subkey_with_flags(INTERNET_SETTINGS, flags)
        .context("cannot open Internet Settings registry key")
}

fn backup_path(dir: &Path) -> std::path::PathBuf {
    dir.join("proxy-backup.json")
}

/// Points the current user's WinINet proxy at the local HTTP CONNECT listener
/// and remembers the previous values for a clean restore. A plain
/// `host:port` value is used because most Windows applications ignore the
/// `socks=` form.
pub fn enable_system_proxy(addr: &str, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = backup_path(dir);
    if !path.exists() {
        let key = settings_key(false)?;
        let backup = ProxyBackup {
            enabled: key.get_value("ProxyEnable").ok(),
            server: key.get_value("ProxyServer").ok(),
            bypass: key.get_value("ProxyOverride").ok(),
        };
        std::fs::write(&path, serde_json::to_vec_pretty(&backup)?)?;
    }
    let key = settings_key(true)?;
    key.set_value("ProxyEnable", &1u32)?;
    key.set_value("ProxyServer", &addr.to_owned())?;
    key.set_value(
        "ProxyOverride",
        &"<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*",
    )?;
    refresh_wininet();
    tracing::info!("system proxy -> {addr}");
    Ok(())
}

pub fn disable_system_proxy(dir: &Path) -> Result<()> {
    let path = backup_path(dir);
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(backup) = serde_json::from_str::<ProxyBackup>(&text) {
            if let Ok(key) = settings_key(true) {
                set_or_delete(&key, "ProxyEnable", backup.enabled);
                set_or_delete(&key, "ProxyServer", backup.server);
                set_or_delete(&key, "ProxyOverride", backup.bypass);
            }
            let _ = std::fs::remove_file(path);
            refresh_wininet();
            return Ok(());
        }
    }
    if let Ok(key) = settings_key(true) {
        let _ = key.set_value("ProxyEnable", &0u32);
    }
    refresh_wininet();
    Ok(())
}

fn set_or_delete<T: winreg::types::ToRegValue>(key: &RegKey, name: &str, value: Option<T>) {
    match value {
        Some(value) => {
            let _ = key.set_value(name, &value);
        }
        None => {
            let _ = key.delete_value(name);
        }
    }
}

fn refresh_wininet() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
    }
}

pub fn autostart_enabled() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey(RUN_KEY)
        .ok()
        .and_then(|key| key.get_value::<String, _>(RUN_VALUE).ok())
        .is_some()
}

pub fn set_autostart(enabled: bool) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(RUN_KEY)?;
    if enabled {
        let exe = std::env::current_exe()?;
        key.set_value(RUN_VALUE, &format!("\"{}\" --minimized", exe.display()))?;
        tracing::info!("autostart enabled");
    } else {
        let _ = key.delete_value(RUN_VALUE);
        tracing::info!("autostart disabled");
    }
    Ok(())
}

pub use crate::tun::{is_elevated, relaunch_elevated};
