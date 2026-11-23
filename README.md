# SafeCircle APK — Technical Review

Static-analysis writeup of `SafeCircle.apk`, covering how the app reads notifications, how its
scam-detection logic works, how it syncs between devices, and whether it leaks sensitive data
(message content, sender identity) off the device.

This was produced by unpacking the APK (manifest, DEX bytecode, resources) with `androguard` —
no dynamic/runtime testing was done.

## Basic app info

| Field | Value |
|---|---|
| Package | `com.aistudio.safecircle.krmxvp` |
| App name | SafeCircle |
| Version | 1.0 |
| Min SDK | 24 |
| Target SDK | 36 |
| Signing | Generic **Android Debug** certificate (not a release key) |

## Permissions requested

- `android.permission.INTERNET`
- `android.permission.ACCESS_NETWORK_STATE`
- `android.permission.POST_NOTIFICATIONS`
- `android.permission.USE_BIOMETRIC` / `USE_FINGERPRINT`
- `android.permission.VIBRATE`
- `com.google.android.providers.gsf.permission.READ_GSERVICES`

Notably **absent**: SMS, contacts, call log, storage. No normal permission grants access to
message content.

## How it actually reads messages

The app declares a real Android **`NotificationListenerService`**
(`com.example.service.SafeCircleNotificationListenerService`), bound with
`android.permission.BIND_NOTIFICATION_LISTENER_SERVICE`. This is not a manifest permission the
user approves in the install dialog — it's a special access toggle the user must enable manually
in system Settings. Once enabled, Android forwards every notification posted on the device to the
app's `onNotificationPosted()` callback.

Inside that callback, the app filters hard before doing anything:

1. Returns immediately unless the notification's package is in a hardcoded allowlist,
   `MONITORED_PACKAGES`:
   - `com.whatsapp`, `com.whatsapp.w4b`
   - `com.google.android.apps.messaging`
   - `com.samsung.android.messaging`
   - `com.android.mms`
   - `org.telegram.messenger`
   - `com.facebook.orca`
2. Ignores ongoing/persistent notifications.
3. Reads only `android.title`, `android.bigText`, and `android.text` from the notification's
   `extras` bundle — the same text already visible in the notification shade. It never reads from
   the messaging app's own storage/database.
4. Requires at least 6 characters of trimmed text or drops the event.

All other apps (banking apps, OTP apps, social media, etc.) are never inspected.

## Scam-detection engine — fully on-device

Matched text is passed to `ScamRuleEngine.evaluate(rawText, sourceApp, senderLabel,
trustedSenderHashes)`. There is **no network call anywhere in this code path** — detection is
regex/keyword matching that runs entirely on the device.

Rule categories found in the bytecode (English + Malayalam patterns):

- Police/court/"digital arrest" impersonation
- OTP / PIN / CVV / password sharing requests
- `.apk` / "install this app" phishing
- Fake bank KYC / "account blocked" messages
- Fake electricity-bill (KSEB) disconnection threats
- Investment/stock-tip scams ("guaranteed returns")
- Lottery / prize-claim scams
- Urgency language ("now", "immediately", "last chance")
- Shortened-URL domains (`bit.ly`, `tinyurl.com`, `cutt.ly`, etc.)
- A hardcoded allowlist of legitimate bank/government domains (`sbi.co.in`, `hdfcbank.com`,
  `rbi.org.in`, `uidai.gov.in`, `kerala.gov.in`, etc.)

Sender identifiers for the "trusted sender" feature are **SHA-256 hashed** before storage
(`senderHash()`), never kept in plaintext.

## Cloud sync

- **Auth:** Google Sign-In via Firebase Auth (`GoogleAuthManager`).
- **Backend:** Firebase Firestore (`FirestoreCircleRepository`) — pairing codes, circle
  membership, alert observation (`observeAlerts`, `observeMembers`, `generatePairCode`,
  `requestJoinByCode`, `publishVerdictAlert`).
- **What gets synced:** the `FirestoreVerdictAlert` object written to Firestore contains only:
  `id`, `circleId`, `elderUid`, `memberUids`, `outcome`, `verdict`, `rulePack`, `signalIds`,
  `sourceApp`, `scannedAtLabel`, `handledByUid`, `handledByName`, timestamps.
  **There is no field for the raw message text anywhere in this model.**
- A `SyncMode` preference and per-member `ShareLevel` control how much metadata is shared.
- `TtsSpeaker` reads alerts aloud (accessibility for elderly users).

## Privacy summary

- ✅ Notification scanning is scoped to a small allowlist of messaging apps.
- ✅ Scam detection runs 100% on-device; no raw text is ever transmitted.
- ✅ Cloud sync model explicitly excludes message content — only verdicts/signals sync.
- ✅ Sender identifiers are hashed (SHA-256), not stored in plaintext, for the trusted-sender list.
- ⚠️ Signed with a debug certificate — not a production release build.
- ⚠️ Contains a parallel "Demo" subsystem (`DemoDatabaseSeed`, `DemoScenario`,
  `triggerDemoScenario`, `simulateOrJoinByCode`, `HIDE_DEMO_MODE`) — some guardian-pairing/alert
  flows may be simulated locally rather than backed by the real Firestore pipeline.
- ⚠️ Package naming (`com.aistudio.safecircle.krmxvp`, root code package `com.example.*`) is
  consistent with an AI app-builder scaffold rather than a hand-built, audited product.

## Files in this project

- `SafeCircle_APK_Review_QA.pdf` — the same findings as a plain-text interview-style Q&A document.
- `README.md` — this file.

## Methodology / tools

- `androguard` (Python) for manifest parsing, DEX class/method/field listing, and raw bytecode
  inspection of key classes (`SafeCircleNotificationListenerService`, `ScamRuleEngine`,
  `FirestoreVerdictAlert`, `UserPreferencesRepository$Keys`).
- No decompiler (jadx/apktool) was available in this environment; findings are based on manifest
  XML, class/field/method signatures, and raw Dalvik bytecode instructions (string constants and
  control flow), not full Java source reconstruction. Logic not visible as explicit strings or
  simple branches (e.g. exact scoring thresholds inside `ScamRuleEngine.evaluate`) was not fully
  traced.
