## Why

Mihomo's REALITY client currently advertises a synthetic Chrome ClientHello, rejects an empty browser fingerprint, and reports an obsolete client version, so current Xray-core servers can reject or uniquely identify it. Mihomo's REALITY server also interprets `max-time-difference` in microseconds while Xray-core defines the setting in milliseconds.

## What Changes

- Make REALITY use an intact selected uTLS browser fingerprint; `chrome` must remain the exact `HelloChrome_Auto` profile including X25519MLKEM768.
- Default an empty REALITY `client-fingerprint` to Chrome Auto, matching Xray-core.
- Advertise an explicit REALITY compatibility version accepted by Xray-core's default `minClientVer` policy.
- **BREAKING**: stop using `support-x25519mlkem768: false` to mutate a selected browser profile. Legacy servers must use an explicit intact legacy fingerprint such as `chrome120`.
- **BREAKING**: interpret inbound `max-time-difference` as milliseconds, matching Xray-core rather than the current accidental microseconds.
- Add public-behavior and end-to-end tests against a launched local Xray-core server, including VLESS TCP and Vision.
- Update uTLS or its fork only if the tests demonstrate a dependency-level incompatibility.

## Capabilities

### New Capabilities

- `reality-compatibility`: Defines Xray-compatible REALITY client fingerprint selection, version authentication, server time tolerance, and end-to-end VLESS interoperability.

### Modified Capabilities

None.

## Impact

Affected areas include REALITY handshake construction in `component/tls`, REALITY fingerprint selection in outbound TLS setup, inbound REALITY configuration, VLESS integration tests, and configuration documentation. Existing configurations that rely on the legacy `support-x25519mlkem768: false` mutation or microsecond `max-time-difference` values must migrate to an explicit legacy fingerprint or millisecond value respectively.
