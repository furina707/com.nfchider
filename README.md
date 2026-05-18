# NFC Hider

An Xposed module that hides NFC (Near Field Communication) from selected apps on Android.

## Usage

1. Install the module in Xposed Installer / LSPosed
2. Enable the module for the target apps
3. NFC will be hidden from those apps

## Compatibility

- Android 10+ (API 29+)
- Xposed Framework / LSPosed

## Build

```bash
git clone https://github.com/furina707/com.nfchider.git
cd com.nfchider
./gradlew assembleRelease
```

## License

This project is licensed under the MIT License.
