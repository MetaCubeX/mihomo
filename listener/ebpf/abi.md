# Shared datapath ABI v1

ABI v1 is shared by Mihomo and Clash Premium.  Map names, capacities, keys,
values, field order, and marks in this document are immutable for v1.

`DAE_TPROXY_MARK` is `0x1dae`; `DAE_BYPASS_MARK` is `0x2dae`.  These are host
byte-order `u32` values. Packet IP bytes and TCP/UDP ports in `redirect_tuple`
are network order; every other multi-byte ABI field is host order.

`abi.h` is authoritative for the C layout and `abi.go` mirrors it.  Both use
explicit fixed-width integers and natural alignment; neither uses packed
structs. The layout tests lock `dae_param` at 44 bytes, `redirect_tuple` at 40,
`redirect_entry` at 20, `direct_track_entry` at 16, and `dae_event` at 72.

| Map | Type | Capacity | Key / value |
| --- | --- | ---: | --- |
| `DAE_PARAM` | array | 1 | `u32` / `dae_param` |
| `BYPASS_*_PORTS`, `PROXY_*_PORTS` | hash | 256 | `u16` / `u8` |
| `BYPASS_*_IPS`, `PROXY_*_IPS` | LPM trie | 1024 | IPv4 key 8 B, IPv6 key 20 B / `u8` |
| `DYNAMIC_BYPASS_DST_IPS` | LRU hash | 16384 | IPv4 4 B / `u8` |
| `DYNAMIC_BYPASS_DST_IP6S` | LRU hash | 4096 | IPv6 16 B / `u8` |
| `REDIRECT_TRACK` | LRU hash | 32768 | `redirect_tuple` / `redirect_entry` |
| `DIRECT_TRACK` | LRU hash | 65536 | `redirect_tuple` / `direct_track_entry` |
| `LISTEN_SOCKET_MAP` | sockmap | 4 | 0 TCP4, 1 TCP6, 2 UDP4, 3 UDP6 |
| `EVENT_RINGBUF` | ring buffer | 262144 bytes | `dae_event` records |

The full static-filter map list is exported in `ABIMaps`.  It deliberately
retains the frozen clash-rs names so a Premium loader can load the same ELF.
