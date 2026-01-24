# Keep Android

Android app for FROST threshold signing with NIP-55 support.

## Requirements

- Android SDK 36 (Android 16)
- Android NDK r29
- Rust 1.85+ with Android targets
- cargo-ndk

## Setup

This project requires the [keep](https://github.com/privkeyio/keep) Rust workspace.

```bash
# Clone both repos side by side
git clone https://github.com/privkeyio/keep
git clone https://github.com/privkeyio/keep-android

# Create symlink to keep workspace
cd keep-android
ln -s ../keep keep
```

## Building

### 1. Build Rust library

```bash
# Add Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Install cargo-ndk
cargo install cargo-ndk

# Build native libraries (builds keep-mobile from ../keep)
./build-rust.sh
```

### 2. Build Android app

```bash
./gradlew assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

## Project Structure

```
keep-android/
├── app/
│   └── src/main/
│       ├── kotlin/io/privkey/keep/
│       │   ├── KeepMobileApp.kt
│       │   ├── MainActivity.kt
│       │   └── uniffi/          # Generated bindings
│       ├── jniLibs/             # Native libraries
│       └── res/
├── build-rust.sh                # Rust cross-compilation script
└── keep -> ../keep              # Symlink to keep workspace
```

## License

AGPL-3.0-or-later
