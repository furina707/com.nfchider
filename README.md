# NFC Hider

[![Build](https://github.com/furina707/com.nfchider/actions/workflows/build.yml/badge.svg)](https://github.com/furina707/com.nfchider/actions/workflows/build.yml)

An Xposed module that hides NFC (Near Field Communication) from selected apps on Android.

## Usage

1. Install the module in Xposed Installer / LSPosed
2. Enable the module for the target apps
3. NFC will be hidden from those apps
4. (Optional) Open the app drawer and launch **NFC Hider** to view module status

## Compatibility

- Android 10+ (API 29+)
- Xposed Framework / LSPosed

## Build

```bash
git clone https://github.com/furina707/com.nfchider.git
cd com.nfchider
./gradlew assembleDebug
```

The debug APK will be at `app/build/outputs/apk/debug/NfcHider-debug.apk`.

> **Note:** The project uses Jetpack Compose for the settings UI. Building requires:
> - JDK 17+
> - Android SDK 34+

## Download

Pre-built APKs are available from [GitHub Actions](https://github.com/furina707/com.nfchider/actions) — click the latest build, then download the `NfcHider` artifact.

## License

This project is licensed under the MIT License.
