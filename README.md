# Keep Android

Android app for FROST threshold signing with NIP-55 support.

## Building

```bash
./gradlew assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

## Features

- NIP-55 Android Signer protocol
- FROST threshold signing (2-of-3, 3-of-5, etc.)
- Biometric authentication
- Hardware-backed key storage (Android Keystore)
- Background signing with persistent permissions

## Development

To rebuild the native libraries from source:

```bash
# Requirements: Rust 1.85+, Android NDK r29, cargo-ndk

# Clone keep workspace
git clone https://github.com/privkeyio/keep ../keep

# Rebuild native libs and bindings
KEEP_REPO=../keep ./build-rust.sh
```

## License

AGPL-3.0-or-later
