<h1 align="center">
  <img src="https://github.com/Dreamacro/clash/raw/master/docs/logo.png" alt="Clash" width="200">
  <br>
  Clash
  <br>
</h1>

<h4 align="center">A rule based proxy in Go.</h4>

<p align="center">
  <a href="https://travis-ci.org/Dreamacro/clash">
    <img src="https://img.shields.io/travis/Dreamacro/clash.svg?style=flat-square"
         alt="Travis-CI">
  </a>
  <a href="https://goreportcard.com/report/github.com/Dreamacro/clash">
      <img src="https://goreportcard.com/badge/github.com/Dreamacro/clash?style=flat-square">
  </a>
  <a href="https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_shield" alt="FOSSA Status"><img src="https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=shield"/></a>
  <a href="https://github.com/Dreamacro/clash/releases">
    <img src="https://img.shields.io/github/release/Dreamacro/clash/all.svg?style=flat-square">
  </a>
</p>

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

In the case of [pm2](https://github.com/Unitech/pm2), we can start the daemon this way:

```sh
pm2 start clash
```

If you have Docker installed, you can run clash directly using `docker-compose`.

[Run clash in docker](https://github.com/Dreamacro/clash/wiki/Run-clash-in-docker)

## Config

Configuration file at `$HOME/.config/clash/config.ini`

Below is a simple demo configuration file:

```ini
[General]
port = 7890
socks-port = 7891

# A RESTful API for clash
external-controller = 127.0.0.1:8080

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

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)

## TODO

- [ ] Complementing the necessary rule operators
