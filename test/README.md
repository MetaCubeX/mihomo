## Mihomo testing suit

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
