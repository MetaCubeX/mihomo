## 1. RED: Compatibility Tests

- [x] 1.1 Add a failing test that captures REALITY's emitted Chrome ClientHello and requires intact X25519MLKEM768 groups and key shares
- [x] 1.2 Add failing transport tests for empty REALITY fingerprint defaulting and explicit `none` rejection
- [x] 1.3 Add a failing handshake test requiring the authenticated REALITY client version to satisfy `26.3.27`
- [x] 1.4 Add a failing inbound configuration test requiring `max-time-difference` milliseconds

## 2. GREEN: Client and Server Behavior

- [x] 2.1 Remove post-build ClientHello mutation and make the legacy ML-KEM support option a compatibility no-op
- [x] 2.2 Default empty REALITY fingerprint selection to Chrome Auto without changing non-REALITY TLS
- [x] 2.3 Replace the obsolete REALITY version bytes with a named `26.3.27` compatibility constant
- [x] 2.4 Convert inbound `max-time-difference` using milliseconds
- [x] 2.5 Update configuration documentation and migration guidance

## 3. Upstream End-to-End Verification

- [x] 3.1 Add a reproducible integration test that launches a supplied Xray-core executable with default `minClientVer`
- [x] 3.2 Prove VLESS TCP over REALITY transfers application data with an empty fingerprint
- [x] 3.3 Prove VLESS Vision over REALITY transfers application data with Chrome Auto
- [x] 3.4 Record the exact Xray-core commit and integration command used for verification

## 4. Completion Audit

- [x] 4.1 Run focused REALITY, VLESS, VMess, and Trojan test packages
- [x] 4.2 Run formatting, static checks, and the project-wide feasible Go test suite
- [x] 4.3 Validate OpenSpec artifacts and confirm every requirement has authoritative evidence
