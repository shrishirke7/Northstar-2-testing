# Shree IT · Universal iPhone & iPad App (`ios-app`)

This folder contains the native **Universal iOS + iPadOS Swift (`WKWebView`)** project (`TARGETED_DEVICE_FAMILY = "1,2"`, `iOS 15.0+`), matching the Android APK (`android-app`):

- Self-signed LAN HTTPS SSL Trust & SHA-256 Pinning (`CertPinStore.swift`)
- Native Camera Photo Capture + Multi-Page File Upload + Voice Lock PCM (`MainViewController.swift`)
- Credentials Vault Black-Screen Screenshot & Screen-Recording Protection (`UITextField.isSecureTextEntry` + `UIScreen.capturedDidChangeNotification`)
- Native Background & Foreground Alert Notifications (`AlertMonitor.swift`) synced with per-user silent/mute rules
- Universal iPhone + iPad responsive layouts & Split View multitasking

## Option 1 — Instant iPhone & iPad App (Zero Mac Required, Works Right Now)
1. Open the Swarnshilp URL in **Safari** on your iPhone or iPad.
2. Tap **Share** (`⎋`) → **Add to Home Screen**.
3. If your server uses local self-signed HTTPS, tap **📱 Install App & SSL Cert** once to install `shree-server-ca.crt` and enable it in **Settings → General → About → Certificate Trust Settings**.

## Option 2 — Build Apple `.ipa` via GitHub Actions Cloud macOS Runner (No Mac Needed!)
1. Push this repo to GitHub and open **Actions → Build Shree IT Universal iOS & iPadOS App (.ipa) → Run workflow**.
2. Download the compiled `Shree-IT-iOS-iPadOS.ipa` artifact.
3. Install onto your iPhone/iPad with **Sideloadly** (Windows/Mac) or **AltStore** using any free Apple ID, OR re-sign with your Apple Developer account for TestFlight / MDM.

## Option 3 — Direct Build on a Mac with Xcode 15+
1. Open `ios-app/ShreeIT.xcodeproj` in Xcode.
2. Select target **ShreeIT → Signing & Capabilities** → choose your Team (or Personal Apple ID).
3. Connect your iPhone or iPad (or select **Any iOS Device (arm64)**) → press **Run (`⌘R`)** or **Product → Archive** to export a signed `.ipa`.
