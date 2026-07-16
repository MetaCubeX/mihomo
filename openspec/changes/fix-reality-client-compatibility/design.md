## Context

Mihomo currently starts from a valid uTLS browser preset and conditionally removes X25519MLKEM768 after `BuildHandshakeState`. That creates a ClientHello no released browser sends. REALITY authentication also embeds `1.8.2`, while Xray-core's JSON server configuration defaults `minClientVer` to `26.3.27`. Empty fingerprint selection fails before REALITY is invoked, and Mihomo's inbound `max-time-difference` conversion is 1000 times smaller than Xray's documented millisecond unit.

The existing Mihomo-to-Mihomo tests cannot detect the version problem because Mihomo's embedded REALITY server does not set a minimum client version. End-to-end evidence must therefore include the local Xray-core checkout at `/Users/jesus/GolandProjects/Xray-core`.

## Goals / Non-Goals

**Goals:**

- Preserve genuine uTLS browser ClientHellos through the REALITY authentication transformation.
- Match Xray-core's empty-fingerprint, minimum-version, and time-unit semantics.
- Prove VLESS TCP and Vision interoperability against a launched Xray-core process.
- Keep ordinary non-REALITY TLS fingerprint selection unchanged.

**Non-Goals:**

- Reimplement Xray's VLESS framing or Vision flow.
- Add Xray's optional ML-DSA-65 configuration in this change.
- Claim that Mihomo is the same product version as Xray-core; the three authentication bytes describe REALITY compatibility only.

## Decisions

### Preserve presets instead of editing ClientHello

`GetRealityConn` will no longer call `BuildRemovedX25519MLKEM768HandshakeState`. The selected uTLS ID is authoritative. Users needing a pre-ML-KEM browser shape select an existing intact preset such as `chrome120`.

The legacy `support-x25519mlkem768` field remains accepted for configuration compatibility but becomes a deprecated no-op. Removing the field immediately would turn existing YAML into an unknown-field failure in strict parsers; mapping `false` to Chrome 120 would still make `client-fingerprint: chrome` dishonest.

### Default only REALITY's empty fingerprint

`StreamTLSConn` will substitute Chrome Auto only when `cfg.Reality != nil` and `cfg.ClientFingerprint == ""`. The shared `GetFingerprint` function remains unchanged so other TLS transports keep their existing standard-library fallback. Explicit `none` remains an error for REALITY.

### Advertise a protocol compatibility constant

REALITY authentication will use a named `[3]byte{26, 3, 27}` compatibility constant and retain the reserved fourth byte as zero. Using Mihomo's release version would remain below Xray's version namespace, while copying Xray's latest release on every update would falsely imply unrelated feature parity. The minimum accepted version is the narrow honest compatibility contract exercised by the end-to-end test.

### Correct time units at the inbound boundary

`listener/reality.Config.Build` will convert the integer `max-time-difference` using `time.Millisecond`. The YAML name stays unchanged and documentation will explicitly state milliseconds.

### Use layered TDD evidence

Fast tests will capture the actual ClientHello emitted by `GetRealityConn`, verify empty-fingerprint routing at `StreamTLSConn`, inspect the public `Config.Build` conversion boundary, and authenticate against a REALITY server with `MinClientVer: []byte{26,3,27}`. A separately invokable integration test will launch the local Xray executable and transfer application data through VLESS TCP and Vision. This keeps ordinary CI deterministic while retaining a reproducible upstream interoperability gate.

### Keep the current uTLS dependency unless evidence requires a fork change

`github.com/metacubex/utls v1.8.7` already defines `HelloChrome_Auto` as Chrome 133, includes X25519MLKEM768 in its supported groups and key shares, and implements the hybrid exchange on both client and server paths. Updating or patching the dependency without a failing dependency-level test would add risk without addressing the Mihomo-side mutation.

## Risks / Trade-offs

- [Old REALITY servers may not support ML-KEM] → Require an explicit intact legacy fingerprint such as `chrome120` rather than emitting a synthetic current-Chrome fingerprint.
- [Correcting milliseconds changes existing effective tolerances] → Document the unit and migration prominently; the old behavior contradicted Xray compatibility.
- [Xray raises its default minimum in the future] → The external integration gate will fail and require an explicit compatibility review rather than silently spoofing a newer version.
- [External integration depends on a local binary/path] → Gate it with an explicit executable environment variable and record the exact Xray commit used for verification.

## Migration Plan

1. Replace reliance on `support-x25519mlkem768: false` with `client-fingerprint: chrome120` only for servers that require a legacy profile.
2. Treat all inbound `max-time-difference` values as milliseconds and adjust values that were chosen around the accidental microsecond conversion.
3. Roll back by reverting the behavior commit; no persisted data migration is involved.

## Open Questions

None. Dependency changes remain conditional on a demonstrated failing uTLS test.

## Verification Evidence

- Xray-core source: `/Users/jesus/GolandProjects/Xray-core` at commit `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` (the executable reports `50231ea-dirty` because that checkout contains unrelated untracked files).
- Xray build: `go build -o /tmp/xray-core-reality ./main` from the Xray-core checkout.
- End-to-end command: `XRAY_BINARY=/tmp/xray-core-reality go test ./listener/inbound -run '^TestVLESSRealityXrayInterop$' -v -count=1`.
- Result: VLESS TCP with an empty fingerprint and VLESS Vision with Chrome Auto both transferred application data successfully through Xray 26.7.11. The JSON server configuration deliberately omitted `minClientVer`, exercising Xray's `26.3.27` default.
