# Short Polling VPN – Android app

An Android wrapper for the Python vpn-poller. Runs the SOCKS5 proxy client
on the device using Chaquopy (embedded CPython).

## Build

1. Install [Android Studio](https://developer.android.com/studio) with
   Android SDK 34, NDK, and Kotlin plugin.
2. Open this directory as an Android project.
3. Wait for Gradle sync to finish (first build may take a while as it
   downloads Python + pip dependencies).
4. Build APK: **Build → Build Bundle(s) / APK(s) → Build APK(s)**.

APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

## Usage

1. Install the APK on your Android device.
2. Open the app.
3. Configure the proxy:
   - **Profiles tab**: create/rename/duplicate/delete named profiles. Each
     profile stores its operation mode (Proxy / VPN), connection settings
     and traffic routing rules. Tap **Set Active** to switch; apply by
     Stop/Start.
   - **Simple tab**: fill in individual fields (server URL, PSK, etc.)
     for the active profile. Changes are saved automatically on every edit.
   - **Config tab**: paste/edit the full JSON config (server block is
     ignored, only client + security sections are used).
4. Tap **Start**. The proxy runs as a foreground service (notification
   in status bar).
5. In Proxy mode, configure your apps or browser to use SOCKS5 proxy at
   `127.0.0.1:8888`.
   - On a non-rooted device, apps must support SOCKS5 natively (e.g.,
     Firefox with proxy extension, Telegram, or use tools like Postern
     / ProxyDroid / Drony to route all traffic).
   - VPN mode (system-wide capture via VpnService) is selected per profile;
     traffic routing rules (allow/block app lists) are stored in the
     profile and applied once VpnService capture is implemented.

## Notes

- The server block in config is ignored on the client — only `client`
  and `security` sections matter.
- Android does **not** support system-wide SOCKS5 proxy without
  additional tools (VpnService / root). Use third-party apps to
  redirect traffic if needed.
- Python dependencies are bundled into the APK (~30 MB extra).
