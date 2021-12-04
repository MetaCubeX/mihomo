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
      - gfw  # `geosite` filter only use fallback server to resolve ip, prevent DNS leaks to unsafe DNS providers.
    domain:
      - +.example.com
    ipcidr:
      - 0.0.0.0/32
```

### TUN configuration
Supports macOS, Linux and Windows.

Support lwIP stack, a lightweight TCP/IP stack, it's recommended set to tun.

On Windows, you should download the [Wintun](https://www.wintun.net) driver and copy `wintun.dll` into Clash home directory.
```yaml
# Enable the TUN listener
tun:
  enable: true
  stack: lwip # lwip(recommended), system or gvisor
  dns-listen: 0.0.0.0:53 # additional dns server listen on TUN
  auto-route: true # auto set global route
```
### Rules configuration
- Support rule `GEOSITE`.
- Support rule `SCRIPT`.
- Support `multiport` condition for rule `SRC-PORT` and `DST-PORT`.
- Support `network` condition for all rules.
- Support source IPCIDR condition for all rules, just append to the end.

The `GEOSITE` databases via https://github.com/Loyalsoldier/v2ray-rules-dat.
```yaml
mode: rule

script:
  shortcuts:
    quic: 'network == "udp" and dst_port == 443'
    privacy: '"analytics" in host or "adservice" in host or "firebase" in host or "safebrowsing" in host or "doubleclick" in host'

rules:
  # rule SCRIPT
  - SCRIPT,quic,REJECT # Disable QUIC, same as rule "DST-PORT,443,REJECT,udp"
  - SCRIPT,privacy,REJECT
    
  # network(tcp/udp) condition for all rules
  - DOMAIN-SUFFIX,bilibili.com,DIRECT,tcp
  - DOMAIN-SUFFIX,bilibili.com,REJECT,udp
    
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
  - GEOIP,private,DIRECT,no-resolve
  - GEOIP,cn,DIRECT
  
  - MATCH,PROXY
```

### Script configuration
Script enables users to programmatically select a policy for the packets with more flexibility.

```yaml
mode: script

rules:
  # the rule GEOSITE just as a rule provider in mode script
  - GEOSITE,category-ads-all,Whatever
  - GEOSITE,youtube,Whatever
  - GEOSITE,geolocation-cn,Whatever
  
script:
  code: |
    def main(ctx, metadata):
      if metadata["process_name"] == 'apsd':
        return "DIRECT"

      if metadata["network"] == 'udp' and metadata["dst_port"] == 443:
        return "REJECT"
    
      host = metadata["host"]
      for kw in ['analytics', 'adservice', 'firebase', 'bugly', 'safebrowsing', 'doubleclick']:
        if kw in host:
          return "REJECT"
    
      now = time.now()
      if (now.hour < 8 or now.hour > 17) and metadata["src_ip"] == '192.168.1.99':
        return "REJECT"
      
      if ctx.rule_providers["geosite:category-ads-all"].match(metadata):
        return "REJECT"
    
      if ctx.rule_providers["geosite:youtube"].match(metadata):
        ctx.log('[Script] domain %s matched youtube' % host)
        return "Proxy"

      if ctx.rule_providers["geosite:geolocation-cn"].match(metadata):
        ctx.log('[Script] domain %s matched geolocation-cn' % host)
        return "DIRECT"
    
      ip = metadata["dst_ip"] 
      if host != "":
        ip = ctx.resolve_ip(host)
        if ip == "":
          return "Proxy"

      code = ctx.geoip(ip)
      if code == "LAN" or code == "CN":
        return "DIRECT"

      return "Proxy" # default policy for requests which are not matched by any other script
```
the context and metadata
```ts
interface Metadata {
  type: string // socks5、http
  network: string // tcp
  host: string
  process_name: string
  src_ip: string
  src_port: int
  dst_ip: string
  dst_port: int
}

interface Context {
  resolve_ip: (host: string) => string // ip string
  geoip: (ip: string) => string // country code
  log: (log: string) => void
  rule_providers: Record<string, { match: (metadata: Metadata) => boolean }>
}
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
    servername: example.com # AKA SNI
    # flow: xtls-rprx-direct # xtls-rprx-origin  # enable XTLS
    # skip-cert-verify: true
    
  - name: "vless-ws"
    type: vless
    server: server
    port: 443
    uuid: uuid
    udp: true
    network: ws
    servername: example.com # priority over wss host
    # skip-cert-verify: true
    ws-path: /path
    ws-headers:
      Host: example.com
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
Create user given name `Clash.Meta`.

Run Meta Kennel by user `Clash.Meta` as a daemon.

Create the systemd configuration file at /etc/systemd/system/clash.service:

```
[Unit]
Description=Clash.Meta daemon, A rule-based proxy in Go.
After=network.target

[Service]
Type=simple
User=Clash.Meta
Group=Clash.Meta
CapabilityBoundingSet=cap_net_admin
AmbientCapabilities=cap_net_admin
Restart=always
ExecStart=/usr/local/bin/Clash.Meta -d /etc/Clash.Meta

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
Clash add field `Process` to `Metadata` and prepare to get process name for Restful API `GET /connections`.

To display process name in GUI please use https://yaling888.github.io/yacd/.

## Development
If you want to build an application that uses clash as a library, check out the the [GitHub Wiki](https://github.com/Dreamacro/clash/wiki/use-clash-as-a-library)

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
* [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)
