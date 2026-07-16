## ADDED Requirements

### Requirement: REALITY preserves the selected browser fingerprint
The REALITY client SHALL send the intact uTLS ClientHello selected by `client-fingerprint` and MUST NOT add, remove, or reorder fingerprint extensions, supported groups, or key shares after uTLS builds it.

#### Scenario: Current Chrome fingerprint
- **WHEN** a REALITY connection uses `client-fingerprint: chrome`
- **THEN** its ClientHello matches `HelloChrome_Auto`, including X25519MLKEM768 in both supported groups and key shares

#### Scenario: Explicit legacy Chrome fingerprint
- **WHEN** a REALITY connection uses `client-fingerprint: chrome120`
- **THEN** it sends the intact Chrome 120 profile without synthesizing a modified current-Chrome profile

#### Scenario: Deprecated ML-KEM support flag
- **WHEN** a configuration contains the legacy `support-x25519mlkem768` option
- **THEN** the option does not mutate the selected browser fingerprint

### Requirement: REALITY defaults an empty browser fingerprint
The TLS transport SHALL select `HelloChrome_Auto` when REALITY is enabled and `client-fingerprint` is empty, while preserving the existing empty-fingerprint behavior for non-REALITY TLS.

#### Scenario: Empty REALITY fingerprint
- **WHEN** REALITY is enabled and `client-fingerprint` is omitted or empty
- **THEN** the connection uses `HelloChrome_Auto` and proceeds with the REALITY handshake

#### Scenario: Explicit none remains invalid for REALITY
- **WHEN** REALITY is enabled and `client-fingerprint` is explicitly `none`
- **THEN** configuration or connection setup fails instead of silently selecting a browser fingerprint

### Requirement: REALITY advertises an accepted compatibility version
The REALITY authentication payload SHALL advertise a named compatibility version that is at least `26.3.27`, with the fourth version byte reserved as zero.

#### Scenario: Xray default minimum client version
- **WHEN** an Xray-core REALITY server uses its default `minClientVer` policy
- **THEN** the server accepts Mihomo's authenticated client version

### Requirement: REALITY server time tolerance uses Xray units
The inbound `max-time-difference` setting SHALL be interpreted as milliseconds, matching Xray-core's JSON configuration.

#### Scenario: Convert configured time tolerance
- **WHEN** inbound REALITY is configured with `max-time-difference: 1500`
- **THEN** the server permits an absolute client clock difference of up to 1500 milliseconds

### Requirement: Mihomo interoperates with a current Xray-core server
The project SHALL provide an end-to-end test that launches a current local Xray-core executable with a real JSON configuration and exercises Mihomo as a VLESS-over-REALITY client.

#### Scenario: VLESS TCP over REALITY
- **WHEN** Mihomo connects to the launched Xray-core server using VLESS TCP, an empty fingerprint, and the server's default REALITY minimum version
- **THEN** application data traverses the connection successfully

#### Scenario: VLESS Vision over REALITY
- **WHEN** Mihomo connects to the launched Xray-core server using `xtls-rprx-vision`, Chrome Auto, and the server's default REALITY minimum version
- **THEN** application data traverses the connection successfully
