# Bundled Windows binaries

These files are shipped with the desktop client so that the TUN ("real VPN")
mode works offline and without downloading anything at runtime.

| File | Version | Purpose | License |
|------|---------|---------|---------|
| `tun2proxy-bin.exe` | 0.8.7 | Creates a Wintun adapter, routes all traffic into it and forwards it to the local SOCKS5 server | MIT — https://github.com/tun2proxy/tun2proxy |
| `wintun.dll` | 0.14.1 (from the tun2proxy release archive) | Layer 3 TUN driver for Windows | Prebuilt Wintun binaries are distributed under a permissive license — https://www.wintun.net/ |

SHA-256:

```
DEE4F05420838F69B0C90D910BBA8A2BF0416EF217D1032D292C12536FE351EB  tun2proxy-bin.exe
E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE  wintun.dll
```

`tun2proxy-bin.exe` is only started on demand, and only by the elevated helper
(`vpn_helper.py`), which listens on `127.0.0.1` and is protected by a random
token. It is never started at application startup.
