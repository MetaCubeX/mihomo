## Mihomo testing suit

### TCP half-close idle cleanup

The portable relay and configuration regression tests run in the root module:

```sh
go test ./common/net ./config ./tunnel -count=1
go test -race ./common/net ./config ./tunnel -run 'TestRelay|TestTCPHalfClose' -count=3
go test ./common/net -run '^$' -bench '^BenchmarkRelay$' -benchmem -count=3
```

The relay benchmark compares the original, disabled, and enabled paths using a
32 KiB in-memory stream. It does not measure real network throughput or connection
setup cost. The disabled path delegates to the original relay; enabled relays
retain its one-worker topology, and start the idle timer only after EOF.

For an optional Windows whole-core reproduction, build a patched core, retain a
stock core, then run from the repository root (Python 3.8+; standard library only):

```sh
make test-halfclose-windows STOCK_CORE=/path/to/stock.exe PATCHED_CORE=/path/to/patched.exe HALFCLOSE_REPORT=/path/to/result.json
# Without make, for example in PowerShell:
python test/halfclose_windows.py --stock C:/cores/stock.exe --patched C:/cores/patched.exe --output C:/cores/halfclose-result.json
```

The fixture starts isolated cores with loopback-only temporary configurations,
enables `tcp-half-close-timeout: {client: 300, server: 30}` only for the patched
case, also runs the patched core with its unchanged disabled defaults, and holds
24 client sending directions open after server EOF. It checks
outbound cleanup and process handle release after 35 seconds. Windows may retain
orphaned FIN_WAIT_2 rows after application Close, so their disappearance is not
required. This manual OS fixture is separate from the portable Go CI tests and
does not change the running proxy, user configuration, or system proxy settings.

### Protocol testing suit

* TCP pingpong test
* UDP pingpong test
* TCP large data test
* UDP large data test

### Protocols

- [x] Shadowsocks
  - [x] Normal
  - [x] ObfsHTTP
  - [x] ObfsTLS
  - [x] ObfsV2rayPlugin
- [x] Vmess
  - [x] Normal
  - [x] AEAD
  - [x] HTTP
  - [x] HTTP2
  - [x] TLS
  - [x] Websocket
  - [x] Websocket TLS
  - [x] gRPC
- [x] Trojan
  - [x] Normal
  - [x] gRPC
- [x] Snell
  - [x] Normal
  - [x] ObfsHTTP
  - [x] ObfsTLS

### Features

- [ ] DNS
  - [x] DNS Server
  - [x] FakeIP
  - [x] Host

### Command

Prerequisite

* docker (support Linux and macOS)

```
$ make test
```

benchmark (Linux)

> Cannot represent the throughput of the protocol on your machine
> but you can compare the corresponding throughput of the protocol on mihomo
> (change chunkSize to measure the maximum throughput of mihomo on your machine)

```
$ make benchmark
```
