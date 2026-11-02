# Target-scoped TCP fallback (experimental)

Related: [#1433](https://github.com/MetaCubeX/mihomo/issues/1433).

`target-fallback` is an opt-in group that makes a bounded route decision for the
actual TCP destination. Existing rules and group types keep their behavior.
No configuration is automatically rewritten.

```yaml
proxies:
  # Documentation-only address; replace with a verified CONNECT proxy.
  - name: ConfirmedParent
    type: http
    server: 192.0.2.10
    port: 8080
proxy-groups:
  - name: ScopedDirect
    type: target-fallback
    proxies: [DIRECT, ConfirmedParent]
    direct-timeout: 800
    proxy-timeout: 2000
    cache-ttl: 300000
    direct-cache-ttl: 1000
    cooldown: 5000
    max-entries: 4096
    direct-address-limit: 1
    monitor-network: true
    network-epoch: initial
rules:
  # Keep existing dedicated, local and explicit routing rules before this scope.
  - AND,((NETWORK,TCP),(GEOIP,CN)),ScopedDirect
  - GEOIP,CN,DIRECT
  # Keep the remaining original rules here.
```

Times are milliseconds. DNS and DIRECT establishment share `direct-timeout`
after the connection enters this group. DNS performed earlier for rule matching
retains its existing behavior. An unresolved destination cannot be classified as
CN by GEOIP; no global DNS-failure catch-all is added.

The first member must be DIRECT; the second is one proxy or a group whose selected
leaf is frozen for this connection. Only HTTP/SOCKS5 CONNECT leaves with literal
server IPs, without multiplexing or a nested dialer proxy, are supported. Initial
unsupported configurations are rejected. Runtime selection of an unsupported
parent does not prevent healthy DIRECT connections.

## Decisions and budgets

An unknown destination tries DIRECT and, if establishment fails, the selected
parent. Each route is entered at most once per call. A terminal error prevents the
tunnel's outer retry loop from multiplying this budget.

Concurrent callers share the initial route decision and retain independent
connections and cancellation. Healthy DIRECT decisions are briefly reusable so
waiters can dial in parallel. A cancelled caller does not create target-wide
cooldown. If a cached route fails before application forwarding, the still-untried
route may be attempted once. Only failure of both routes creates cooldown.

Route preference is keyed by normalized hostname and port, or IP and port when no
hostname is available. Successful cache hits do not extend expiry. Expiry is lazy;
there is no historical-target probe timer. Cache capacity is bounded. Link/route
notifications clear only this group's decisions; parent selection and configured
interface/mark changes also invalidate decisions. Existing streams are not closed.
DNS-only network changes without a notification may require expiry or a manual
flush.

Local/private, loopback, link-local, multicast and CGNAT/Tailscale addresses remain
DIRECT-only, including protected addresses returned by DNS. Other dedicated
routes must still precede the opt-in rule as usual.

`direct-address-limit` defaults to 1. Setting it to 2 permits at most two distinct
addresses for a destination that was unresolved on entry, sharing the same DNS/TCP
budget. It does not blindly try alternate addresses after GEOIP selected an IP.

## Confirmation and protocol limits

Success means TCP establishment or an acknowledged target CONNECT, not a valid
TLS session or successful application request. The parent must actually confirm
target establishment. Some gateways acknowledge CONNECT before dialing the target;
placing such a gateway in front of another proxy invalidates this guarantee.
Loopback/unspecified parent endpoints are rejected unless explicitly enabled with
`allow-loopback-parent: true`; that override is not proof of correct semantics.

The SOCKS5 confirmed-dial entry point checks reply status and preserves the
existing adapter lifecycle wrapper. It is used only by this group; legacy SOCKS5
call sites retain their current behavior.

TLS/application failures and resets after establishment are not transparently
replayed. POST bodies, media segments and partially transferred streams are not
resent by this group. UDP/QUIC are unsupported by the group; the example retains
the original DIRECT rule for UDP. Shadowsocks and other transports without this
confirmed CONNECT interface are outside this prototype's supported parent set.

## Cache API

The existing controller authentication applies:

- `GET /proxies/{name}/route-cache` returns aggregate counts only.
- `DELETE /proxies/{name}/route-cache` clears future route decisions.

Neither endpoint returns target history or closes established connections.
