<h1 align="center">
  <img src="https://github.com/Dreamacro/clash/raw/master/docs/logo.png" alt="Clash" width="200">
  <br>Clash<br>
</h1>

<h4 align="center">A rule-based tunnel in Go.</h4>

<p align="center">
  <a href="https://github.com/Dreamacro/clash/actions">
    <img src="https://img.shields.io/github/workflow/status/Dreamacro/clash/Go?style=flat-square" alt="Github Actions">
  </a>
  <a href="https://goreportcard.com/report/github.com/Dreamacro/clash">
    <img src="https://goreportcard.com/badge/github.com/Dreamacro/clash?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/Dreamacro/clash?style=flat-square">
  <a href="https://github.com/Dreamacro/clash/releases">
    <img src="https://img.shields.io/github/release/Dreamacro/clash/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/Dreamacro/clash/releases/tag/premium">
    <img src="https://img.shields.io/badge/release-Premium-00b4f0?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, Shadowsocks, Trojan, Snell protocol support for remote connections
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node based off latency
- Remote providers, allowing users to get node lists remotely instead of hardcoding in config
- Netfilter TCP redirecting. Deploy Clash on your Internet gateway with `iptables`.
- Comprehensive HTTP RESTful API controller

## Getting Started
Documentations are now moved to [GitHub Wiki](https://github.com/Dreamacro/clash/wiki).

## Advanced usage for this branch
### DNS configuration
Support resolve ip with a proxy tunnel.

Support `geosite` with `fallback-filter`.
 ```yaml
 dns:
   enable: true
   use-hosts: true
   ipv6: false
   enhanced-mode: fake-ip
   fake-ip-range: 198.18.0.1/16
   listen: 127.0.0.1:6868
   default-nameserver:
     - 119.29.29.29
     - 114.114.114.114
   nameserver:
     - https://doh.pub/dns-query
     - tls://223.5.5.5:853
   fallback:
     - 'https://1.0.0.1/dns-query#Proxy'  # append the proxy adapter name to the end of DNS URL with '#' prefix.
     - 'tls://8.8.4.4:853#Proxy'
   fallback-filter:
     geoip: false
     geosite:
       - gfw  # `geosite` filter only use fallback server to resolve ip, prevent DNS leaks to untrusted DNS providers.
     domain:
       - +.example.com
     ipcidr:
       - 0.0.0.0/32
 ```

### TUN configuration
Supports macOS, Linux and Windows.

On Windows, you should download the [Wintun](https://www.wintun.net) driver and copy `wintun.dll` into the system32 directory.
```yaml
# Enable the TUN listener
tun:
  enable: true
  stack: gvisor # System or gVisor
  # device: tun://utun8 # or fd://xxx, it's optional
  dns-hijack: 
    - 0.0.0.0:53 # hijack all
  auto-route: true # auto set global route
```
### Rules configuration
- Support rule `GEOSITE`.
- Support `multiport` condition for rule `SRC-PORT` and `DST-PORT`.
- Support `network` condition for all rules.
- Support `process` condition for all rules.
- Support source IPCIDR condition for all rules, just append to the end.

The `GEOSITE` databases via https://github.com/Loyalsoldier/v2ray-rules-dat.
```yaml
rules:
  # network condition for all rules
  - DOMAIN-SUFFIX,example.com,DIRECT,tcp
  - DOMAIN-SUFFIX,example.com,REJECT,udp

  # process condition for all rules (add 'P:' prefix)
  - DOMAIN-SUFFIX,example.com,REJECT,P:Google Chrome Helper

  # multiport condition for rules SRC-PORT and DST-PORT
  - DST-PORT,123/136/137-139,DIRECT,udp
  
  # rule GEOSITE
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,icloud@cn,DIRECT
  - GEOSITE,apple@cn,DIRECT
  - GEOSITE,apple-cn,DIRECT
  - GEOSITE,microsoft@cn,DIRECT
  - GEOSITE,facebook,PROXY
  - GEOSITE,youtube,PROXY
  - GEOSITE,geolocation-cn,DIRECT
  - GEOSITE,geolocation-!cn,PROXY

  # source IPCIDR condition for all rules in gateway proxy
  #- GEOSITE,geolocation-!cn,REJECT,192.168.1.88/32,192.168.1.99/32
  
  - GEOIP,telegram,PROXY,no-resolve
  - GEOIP,lan,DIRECT,no-resolve
  - GEOIP,cn,DIRECT

  - MATCH,PROXY
```

### Proxies configuration
Support outbound transport protocol `VLESS`.

The XTLS only support TCP transport by the XRAY-CORE.
```yaml
proxies:
  - name: "vless-tcp"
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    servername: example.com
    # flow: xtls-rprx-direct # xtls-rprx-origin  # enable XTLS
    # skip-cert-verify: true
```

### IPTABLES auto-configuration
Only work on Linux OS who support `iptables`, Clash will auto-configuration iptables for tproxy listener when `tproxy-port` value isn't zero.

If `TPROXY` is enabled, the `TUN` must be disabled.
```yaml
# Enable the TPROXY listener
tproxy-port: 9898
# Disable the TUN listener
tun:
  enable: false
```
Run Clash as a daemon.

Create the systemd configuration file at /etc/systemd/system/clash.service:
```shell
[Unit]
Description=Clash daemon, A rule-based proxy in Go.
After=network.target

[Service]
Type=simple
CapabilityBoundingSet=cap_net_admin
Restart=always
ExecStart=/usr/local/bin/clash -d /etc/clash

[Install]
WantedBy=multi-user.target
```
Launch clashd on system startup with:
```shell
$ systemctl enable clash
```
Launch clashd immediately with:
```shell
$ systemctl start clash
```

### Display Process name
Add field `Process` to `Metadata` and prepare to get process name for Restful API `GET /connections`.

To display process name in GUI please use https://yaling888.github.io/yacd/.

## Development
If you want to build an application that uses clash as a library, check out the the [GitHub Wiki](https://github.com/Dreamacro/clash/wiki/use-clash-as-a-library)

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)
