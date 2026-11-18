# Shared datapath ABI v2

ABI v2 pins a connection to a data-plane owner. Map names, capacities, keys,
values, field order, and marks below are immutable for v2.

`DAE_TPROXY_MARK` is `0x1dae`; `DAE_BYPASS_MARK` is `0x2dae`. Packet IP bytes
and TCP/UDP ports in `redirect_tuple` are network order; other multi-byte ABI
fields are host order. `abi.h` is authoritative and `abi.go` mirrors it.

`flow_owner_entry` is `{u64 last_seen_ns, u8 owner, u8 pad[7]}`. The only
owners are DIRECT (1) and MIHOMO (2). Both forward and reverse
`redirect_tuple` keys are installed at the first TCP SYN or UDP packet. A
destination policy change never modifies an existing owner.

| Map | Type | Capacity | Key / value |
| --- | --- | ---: | --- |
| `DAE_PARAM` | array | 1 | `u32` / `dae_param` |
| `BYPASS_*_PORTS`, `PROXY_*_PORTS` | hash | 256 | `u16` / `u8` |
| `BYPASS_*_IPS`, `PROXY_*_IPS` | LPM trie | 65536 | IPv4 key 8 B, IPv6 key 20 B / `u8` |
| `DYN_DIRECT4`, `DYN_PROXY4` | LRU hash | 16384 | IPv4 4 B / `u8` |
| `DYN_DIRECT6`, `DYN_PROXY6` | LRU hash | 4096 | IPv6 16 B / `u8` |
| `REDIRECT_TRACK` | LRU hash | 32768 | `redirect_tuple` / `redirect_entry` |
| `FLOW_OWNER` | LRU hash | 65536 | `redirect_tuple` / `flow_owner_entry` |
| `LISTEN_SOCKET_MAP` | sockmap | 4 | 0 TCP4, 1 TCP6, 2 UDP4, 3 UDP6 |
| `EVENT_RINGBUF` | ring buffer | 262144 bytes | `dae_event` records |

Dynamic proxy entries veto dynamic and static DIRECT entries while a new flow
is classified. The old `DIRECT_TRACK` and `DYNAMIC_BYPASS_DST_*` maps are ABI
v1 only and must not be loaded with v2.
