//! Short Polling VPN — minimal high-performance Rust client.

pub mod cdn;
pub mod control;
pub mod crypto;
pub mod frame;
pub mod logging;
pub mod routing;
pub mod socks;
pub mod store;
pub mod subscription;
pub mod test_profile;
pub mod tunnel;

#[cfg(all(feature = "gui", windows))]
pub mod gui;
#[cfg(all(feature = "gui", windows))]
pub mod platform;
#[cfg(all(feature = "gui", windows))]
pub mod tun;

#[cfg(feature = "tui")]
pub mod tui;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
