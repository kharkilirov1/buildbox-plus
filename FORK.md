# BuildBox Plus (private→public fork)

Fork of **BuildBox 2.0.2** by Miguel Villarroel ([@MikeBuildsApp](https://x.com/MikeBuildsApp)).

Base: official source archive `BuildBox-v2.0.0-source.zip`
(https://github.com/mikevillarroel/buildbox-ios/releases/tag/v2.0.0). Upstream publishes
only the 2.0.0 sources; 2.0.1/2.0.2 are binary-only releases. There is no `.xcodeproj`
in the archive — the project is generated from `project.yml` with XcodeGen in CI.

## Why this fork

Upstream BuildBox can only sign with a `.p12` + `.mobileprovision` the user already owns.
This fork adds:

1. **Apple ID signing** — sign in with a free Apple ID, register the device, create a
   development certificate, register App IDs and fetch a provisioning profile inside the
   app (the flow iLoader / SideStore perform on a PC or on-device). Engine: the MIT
   licensed [`isideload`](https://github.com/nab138/isideload) Rust crate, cross-compiled
   to `aarch64-apple-ios` and linked as a static library behind a small C ABI bridge.
2. **Signature auto-refresh** — keep the app's own free-developer signature alive past
   Apple's 7-day limit: refresh on launch + `BGAppRefreshTask`, re-sign the app bundle
   with zsign, reinstall it through the existing local HTTPS installer
   (`buildbox.localhost.direct`, `itms-services`). Installation is confirmed by iOS, so
   the refresh is semi-automatic (one tap), not silent.

## Status

- [x] Source reconstructed (`project.yml` + `Info.plist` from the shipped 2.0.2 IPA)
- [x] CI build green: unsigned arm64 IPA as a GitHub Actions artifact
      (`BuildBox-fork-ipa`, bundle `com.mikevillarroel.buildbox`, version 2.1.0 build 100)
- [x] Rust `isideload` 0.5.0 cross-compiles for `aarch64-apple-ios`
      (features: `tokio-mt`, `fs-storage`, `install`) — static lib builds in CI
- [x] C ABI bridge: `bbs_init` / `bbs_login` (2FA callback) / teams / cert + App ID +
      profile / `bbs_export_identity` + `bbs_sign_ipa` (verified linked into the app binary)
- [x] Swift module `AppleIDAuth` (Keychain storage, Apple ID section in the Sign tab)
- [x] `SelfRefresh` manager (profile expiry check, silent re-login with the saved Keychain credential, re-sign own bundle, self-install,
      `BGAppRefreshTask`, expiry notification)
- [ ] End-to-end on device (blocked: iPhone not connected to this PC): sign fork IPA via iLoader, install, log in with Apple ID,
      sign a test app with the account-issued certificate, verify refresh

## Build

`.github/workflows/build.yml`: XcodeGen → `xcodebuild -sdk iphoneos` (unsigned) →
`Payload/BuildBox.app` → `BuildBox-fork.ipa` → artifact.
`.github/workflows/rust-ios-spike.yml`: `cargo build --target aarch64-apple-ios` for
`bridge/` (static library `libbuildbox_sideload.a`).

The IPA artifact is **unsigned** and must be signed (iLoader with a free Apple ID)
before installing.

## Notes

- Free Apple ID limits: 3 installed apps, 10 App IDs / 7 days, 7-day certificate.
- Refresh via `itms-services` shows the system install confirmation → one tap.
- Fully silent refresh would need a SideStore-style pairing/VPN/`installation_proxy`
  stack; out of scope for now.

## Build notes

- BuildBox-fork.ipa (unsigned, 23.5 MB, version 2.1.0) contains the Rust engine
  (bs_login, bs_export_identity, bs_sign_ipa symbols present) — verified by
  inspecting the CI artifact.
- Account signing does not use bs_sign_ipa's team-prefixed bundle id: the app exports
  a p12 + provisioning profile for the IPA's own bundle id and signs with the existing
  zsign pipeline, so the installed app keeps its bundle id and self-refresh installs as
  an update.


## PC fallback (`pc-tool/`)

`bb-install` (Rust, host build) signs an IPA with the Apple ID and installs it over
USB through `idevice`/usbmuxd — no iLoader GUI needed. It reads the Apple ID password
and certificate from the Windows Credential Manager service `iloader` that iLoader
already populated, so it reuses the same certificate instead of requesting a new one.

```
cd pc-tool && cargo build --release
target/release/bb-install.exe --check-device
target/release/bb-install.exe --list-certs --apple-id <apple-id>
target/release/bb-install.exe --ipa ..\ci-out4\BuildBox-fork.ipa --apple-id <apple-id> --machine-name "<iLoader machine name>"
```

`--check-device` works without credentials (usbmuxd reachable, waits for the iPhone).
Verified 2026-10-24: `--help` and `--check-device` run; usbmuxd reports "no devices
found" while the iPhone is disconnected, Apple Mobile Device Service is running.


### 2026-10-24 — auto-refresh sign-in

When the signature is within two days of expiry and no live session exists, the app now
repeats the Apple ID sign-in with the Keychain-saved password; if Apple asks for a
2FA code, the prompt sheet is presented from ContentView (works on any tab) and the
refresh continues after the code is entered.

