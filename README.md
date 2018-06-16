# Clash

[![TravisCI](https://img.shields.io/travis/Dreamacro/clash.svg?style=flat-square)](https://travis-ci.org/Dreamacro/clash)

A rule based proxy in Go.

## Features

- HTTP/HTTPS and SOCKS proxy
- Surge like configuration
- GeoIP rule support

## Install

You can build from source:

```sh
go get -u -v github.com/Dreamacro/clash
```

Pre-built binaries are available: [release](https://github.com/Dreamacro/clash/releases)

Requires Go >= 1.10.

## Daemon

Unfortunately, there is no native elegant way to implement golang's daemon.

So we can use third-party daemon tools like pm2, supervisor, and so on.

In the case of pm2, we can start the daemon this way:

```sh
pm2 start clash
```

## Config

Configuration file at `$HOME/.config/clash/config.ini`

Below is a simple demo configuration file:

```ini
[General]
port = 7890
socks-port = 7891

[Proxy]
# name = ss, server, port, cipher, password
# The types of cipher are consistent with go-shadowsocks2
# support AEAD_AES_128_GCM AEAD_AES_192_GCM AEAD_AES_256_GCM AEAD_CHACHA20_POLY1305 AES-128-CTR AES-192-CTR AES-256-CTR AES-128-CFB AES-192-CFB AES-256-CFB CHACHA20-IETF XCHACHA20
Proxy1 = ss, server1, port, AEAD_CHACHA20_POLY1305, password
Proxy2 = ss, server2, port, AEAD_CHACHA20_POLY1305, password

[Proxy Group]
# url-test select which proxy will be used by benchmarking speed to a URL.
# name = url-test, [proxys], url, interval(second)
Proxy = url-test, Proxy1, Proxy2, http://www.google.com/generate_204, 300

[Rule]
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,google,Proxy
DOMAIN-SUFFIX,ad.com,REJECT
GEOIP,CN,DIRECT
FINAL,,Proxy # note: there is two ","
```

## TODO

- [ ] Complementing the necessary rule operators
