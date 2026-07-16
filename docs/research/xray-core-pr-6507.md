# Xray-core PR #6507: minimum REALITY client version

Date reviewed: 2026-07-16

## What the PR changes

[XTLS/Xray-core#6507](https://github.com/XTLS/Xray-core/pull/6507) is an open, one-file change to `infra/conf/transport_security.go`. It does not change the REALITY wire format or handshake implementation. Its patch:

- defines the minimum accepted version as the three bytes `{26, 3, 27}`;
- keeps `26.3.27` as the default when `minClientVer` is omitted;
- requires an explicit `minClientVer` to contain exactly three decimal components, each fitting in one byte;
- rejects an explicit value lower than `26.3.27`.

The default itself predates the PR. It was introduced by Xray-core commit [`af7eb680`](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770). PR #6507 commit [`2f86dd39`](https://github.com/XTLS/Xray-core/commit/2f86dd3909a28ce514de195004c7da622e799e24) mainly prevents operators from lowering that default.

The three version bytes are compared as a big-endian integer by the REALITY server. Xray clients fill them from `core.Version_x`, `core.Version_y`, and `core.Version_z`, so this is an implementation release marker rather than a newly negotiated protocol version.

## Motivation and current upstream position

The linked maintainer discussion ties the `26.3.27` floor to TLS fingerprint risk, not to a cryptographic or wire-compatibility break. The discussion explicitly calls out Mihomo's use of an old Chrome 120 fingerprint and the distinguishability created by modifying a current fingerprint to remove `X25519MLKEM768`: [Xray-core#6181 comment](https://github.com/XTLS/Xray-core/pull/6181#issuecomment-4567373533).

PR #6507 is not merged. In its discussion, RPRX suggests warnings may be more appropriate than making the lower bound impossible to override: warn that the default accepts only Xray-core `v26.3.27+`, and warn about fingerprint risk when a non-default value is used. Therefore the enforcement behavior should not yet be treated as settled upstream policy.

The current patch also cannot compile as posted: it declares `minClientVer := [...]byte{26, 3, 27}` at package scope, where Go requires a `var` declaration. This is another reason not to copy the diff literally.

## Impact on Mihomo

At the review baseline, Mihomo had two independent differences from Xray-core:

1. The REALITY client writes the hard-coded version `1.8.2` into the first three bytes of the encrypted Session ID in `component/tls/reality.go`. An Xray server using the current default minimum `26.3.27` will reject that value before short-ID acceptance.
2. The Mihomo REALITY inbound builds `utls.RealityConfig` without setting `MinClientVer`, so its server accepts every client version. The configuration structs do not currently expose minimum or maximum client version fields.

The pinned `github.com/metacubex/utls v1.8.7` dependency already supports `RealityConfig.MinClientVer` and `MaxClientVer`, so no dependency upgrade is required just to add the server-side bound.

There was also a fingerprint concern separate from the numeric version. Unless `support-x25519mlkem768` was enabled, `component/tls/reality.go` called `BuildRemovedX25519MLKEM768HandshakeState`, which removed the post-quantum group from an otherwise current uTLS ClientHello. This is the distinguishability pattern discussed upstream. Merely changing `1.8.2` to `26.3.27` would have restored numeric compatibility without resolving that fingerprint risk.

## Suggested implementation split

Keep the work in separate commits so compatibility and policy remain reviewable:

1. **Client compatibility:** replace the stale `1.8.2` literal with a named REALITY compatibility version and test the three emitted bytes. Using `26.3.27` will pass the Xray default, but the commit message should state clearly that this is compatibility metadata, not Mihomo's own release version.
2. **Server policy (optional):** decide whether Mihomo should default `MinClientVer` to `26.3.27`, expose a configurable minimum, only warn, or preserve its current permissive behavior. Copying PR #6507 exactly would be a breaking policy change for older and third-party clients.
3. **Fingerprint safety:** separately decide whether an unmodified current Chrome fingerprint with `X25519MLKEM768` should become the default, while retaining an explicit legacy compatibility mode for old REALITY servers.

Minimum tests for a future fix:

- assert the client writes the intended version bytes into the REALITY Session ID before encryption;
- verify server boundary behavior for `26.3.26`, `26.3.27`, and a greater version if a minimum is added;
- validate exactly three components in the range `0..255` if the setting is exposed;
- add an Xray process interoperability test against a server using its default `minClientVer`.

## Implemented resolution

The `fix/reality-min-client-version` branch resolves the client-side findings together: it preserves the selected uTLS fingerprint, defaults an omitted REALITY fingerprint to Chrome Auto, advertises the tested `26.3.27` compatibility version, and interprets inbound `max-time-difference` in Xray-compatible milliseconds. The legacy `support-x25519mlkem768` field remains accepted as a deprecated no-op; old servers must use an explicit intact legacy preset such as `chrome120`.

The end-to-end gate launches Xray-core 26.7.11 from commit `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` with its default `minClientVer` and verifies both plain VLESS TCP with an empty fingerprint and VLESS Vision with Chrome Auto.
