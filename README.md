# Clash

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

Requires Go >= 1.10.

## Config

Configuration file at `$HOME/.config/clash/config.ini`

Below is a simple demo configuration file:

```ini
[General]
port = 7890
socks-port = 7891

[Proxy]
# name = ss, server, port, cipter, password
Proxy = ss, server, port, AEAD_CHACHA20_POLY1305, password

[Rule]
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,google,Proxy
DOMAIN-SUFFIX,ad.com,REJECT
GEOIP,CN,DIRECT
FINAL,,Proxy
```

## TODO

- [ ] Complementing the necessary rule operators
