# Keep: FROST threshold signer for Android

[Keep](https://github.com/privkeyio/keep-android) is a [FROST](docs/README.md) (Flexible Round-Optimized Schnorr Threshold Signatures) threshold signing app and dedicated Nostr event signer for Android. It allows users to hold FROST key shares on their phone and sign Nostr events without any single device ever holding the full private key. Keep implements the [NIP-55](https://github.com/nostr-protocol/nips/blob/master/55.md) Android Signer protocol and [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signing, so any compatible Nostr client can request signatures directly.

Keep serves as a dedicated Nostr event signer that keeps private key material segregated from client apps, implementing NIP-55 and NIP-46 with per-app permissions, background signing, and multiple account support. Keep goes further by splitting keys into FROST threshold shares (2-of-3, 3-of-5, etc.) so that no single device ever holds the complete private key.

<div align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/privkeyio/keep-android/ci.yml?labelColor=27303D)](https://github.com/privkeyio/keep-android/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/privkeyio/keep-android?labelColor=27303D&color=0877d2)](/LICENSE)

</div>

# Features

- FROST threshold signing (2-of-3, 3-of-5, etc.)
- NIP-55 Android Signer protocol (intents + content provider)
- NIP-46 remote signing (bunker service)
- Import and export FROST shares via QR code or text
- Import existing nsec keys
- Multiple account support
- Per-app signing permissions and policies
- Signing history and audit log
- Biometric and PIN authentication
- Hardware-backed key storage (Android Keystore)
- Kill switch for emergency key deletion
- SOCKS proxy support (Tor)
- NIP-44 encryption and decryption
- Background signing with configurable rate limits
- Certificate pinning for relay connections
- Encrypted backup and restore
- Bitcoin wallet descriptor coordination (multisig)

# Download

[<img src="./assets/zapstore.svg"
alt="Get it on Zapstore"
height="70">](https://zapstore.dev/apps/io.privkey.keep)
[<img src="./assets/obtainium.png"
alt="Get it on Obtainium"
height="70">](https://github.com/ImranR98/Obtainium)
[<img src="https://github.com/machiav3lli/oandbackupx/raw/034b226cea5c1b30eb4f6a6f313e4dadcbb0ece4/badge_github.png"
alt="Get it on GitHub"
height="70">](https://github.com/privkeyio/keep-android/releases)
[<img src="https://fdroid.gitlab.io/artwork/badge/get-it-on.png"
alt="Get it on F-Droid"
height="70">](https://f-droid.org/en/packages/io.privkey.keep/)

# Usage

Any Nostr client that supports NIP-55 or NIP-46 can use Keep for signing.

Supported NIP-55 operations: `get_public_key`, `sign_event`, `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, `nip44_decrypt`, `decrypt_zap_event`.

# Building

Exact toolchain versions are required. The build fails fast on any mismatch.

- Rust `1.89.0` (pinned in `keep/rust-toolchain.toml`, auto-selected by rustup)
- Android NDK `29.0.14206865` (install via `sdkmanager "ndk;29.0.14206865"`)
- `cargo-ndk` `4.1.2`: `cargo install --locked cargo-ndk --version 4.1.2`
- JDK 17

```bash
git clone https://github.com/privkeyio/keep keep
./gradlew assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`. Gradle rebuilds the Rust libraries automatically when sources change. Set `KEEP_REPO` if the `keep` checkout lives elsewhere.

Run `scripts/check-toolchain-pins.sh` to verify pinned versions are consistent across build scripts and CI workflows.

# Contributing

[GitHub issues](https://github.com/privkeyio/keep-android/issues) and [pull requests](https://github.com/privkeyio/keep-android/pulls) are welcome.

Translations are welcome. Seed locales (Portuguese (Brazil), Spanish, German, Japanese) live under `app/src/main/res/values-<lang>[-r<REGION>]/strings.xml`; store listings live under `fastlane/metadata/android/<locale>/`. A managed translation platform (Crowdin or Weblate) is on the backlog; until it lands, translations are contributed via pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full translator workflow. `scripts/check-locale-drift.sh` fails CI if a locale is missing any translatable key from the default `values/strings.xml`.

By contributing to this repository, you agree to license your work under the MIT license. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.

# License

MIT
