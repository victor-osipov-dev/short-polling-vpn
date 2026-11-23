//! Embeds the application icon into the Windows executable.
//!
//! The resource compiler (`rc.exe`) ships with the Windows SDK that the MSVC
//! toolchain already needs, so no extra build dependency is required.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out = PathBuf::from(env::var("OUT_DIR").expect("out dir"));
    let icon = manifest.join("assets").join("icon.ico");
    if !icon.exists() {
        println!("cargo:warning=assets/icon.ico is missing, the executable keeps the default icon");
        return;
    }

    let rc_file = out.join("spvpn.rc");
    let icon_path = icon.display().to_string().replace('\\', "\\\\");
    std::fs::write(&rc_file, format!("1 ICON \"{icon_path}\"\n")).expect("write resource script");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86") => "x86",
        _ => "x64",
    };
    let Some(rc) = find_rc(arch) else {
        println!("cargo:warning=rc.exe not found, the executable keeps the default icon");
        return;
    };

    let res = out.join("spvpn.res");
    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res)
        .arg(&rc_file)
        .status()
        .expect("run rc.exe");
    if !status.success() {
        println!("cargo:warning=rc.exe failed, the executable keeps the default icon");
        return;
    }
    println!("cargo:rustc-link-arg={}", res.display());
}

fn find_rc(arch: &str) -> Option<PathBuf> {
    if let Ok(output) = Command::new("where").arg("rc.exe").output() {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let path = PathBuf::from(line.trim());
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    let kits = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(kits)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    versions.sort();
    versions
        .into_iter()
        .rev()
        .map(|version| version.join(arch).join("rc.exe"))
        .find(|candidate| candidate.is_file())
}
