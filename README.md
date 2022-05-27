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
### General configuration
```yaml
sniffing: true # Sniff TLS SNI

force-cert-verify: true # force verify TLS Certificate, prevent machine-in-the-middle attacks
```

### MITM configuration
A root CA certificate is required, the 
MITM proxy server will generate a CA certificate file and a CA private key file in your Clash home directory, you can use your own certificate replace it. 

Need to install and trust the CA certificate on the client device, open this URL [http://mitm.clash/cert.crt](http://mitm.clash/cert.crt) by the web browser to install the CA certificate, the host name 'mitm.clash' was always been hijacked.

NOTE: this feature cannot work on tls pinning

WARNING: DO NOT USE THIS FEATURE TO BREAK LOCAL LAWS

```yaml
# Port of MITM proxy server on the local end
mitm-port: 7894

# Man-In-The-Middle attack
mitm:
  hosts: # use for others proxy type. E.g: TUN, socks
    - +.example.com
  rules: # rewrite rules
    - '^https?://www\.example\.com/1 url reject' # The "reject" returns HTTP status code 404 with no content.
    - '^https?://www\.example\.com/2 url reject-200' # The "reject-200" returns HTTP status code 200 with no content.
    - '^https?://www\.example\.com/3 url reject-img' # The "reject-img" returns HTTP status code 200 with content of 1px png.
    - '^https?://www\.example\.com/4 url reject-dict' # The "reject-dict" returns HTTP status code 200 with content of empty json object.
    - '^https?://www\.example\.com/5 url reject-array' # The "reject-array" returns HTTP status code 200 with content of empty json array.
    - '^https?://www\.example\.com/(6) url 302 https://www.example.com/new-$1'
    - '^https?://www\.(example)\.com/7 url 307 https://www.$1.com/new-7'
    - '^https?://www\.example\.com/8 url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: haha-wriohoh$2' # The "request-header" works for all the http headers not just one single header, so you can match two or more headers including CRLF in one regular expression.
    - '^https?://www\.example\.com/9 url request-body "pos_2":\[.*\],"pos_3" request-body "pos_2":[{"xx": "xx"}],"pos_3"'
    - '^https?://www\.example\.com/10 url response-header (\r\n)Tracecode:.+(\r\n) response-header $1Tracecode: 88888888888$2'
    - '^https?://www\.example\.com/11 url response-body "errmsg":"ok" response-body "errmsg":"not-ok"'
```

### DNS configuration
Support resolve ip with a proxy tunnel.

Support `geosite` with `fallback-filter`.

Use `curl -X POST controllerip:port/cache/fakeip/flush` to flush persistence fakeip
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
Simply add the following to the main configuration:

#### NOTE:
> auto-route and auto-detect-interface only available on macOS, Windows and Linux, receive IPv4 traffic

```yaml
tun:
  enable: true
  stack: system # or gvisor
  # device: tun://utun8 # or fd://xxx, it's optional
  # dns-hijack:
  #   - 8.8.8.8:53
  #   - tcp://8.8.8.8:53
  #   - any:53
  #   - tcp://any:53
  auto-route: true # auto set global route
  auto-detect-interface: true # conflict with interface-name
```
or
```yaml
interface-name: en0

tun:
  enable: true
  stack: system # or gvisor
  # dns-hijack:
  #   - 8.8.8.8:53
  #   - tcp://8.8.8.8:53
  auto-route: true # auto set global route
```
It's recommended to use fake-ip mode for the DNS server.

Clash needs elevated permission to create TUN device:
```sh
$ sudo ./clash
```
Then manually create the default route and DNS server. If your device already has some TUN device, Clash TUN might not work. In this case, fake-ip-filter may helpful.

Enjoy! :)

#### For Windows:
```yaml
tun:
  enable: true
  stack: gvisor # or system
  dns-hijack:
    - 198.18.0.2:53 # when `fake-ip-range` is 198.18.0.1/16, should hijack 198.18.0.2:53
  auto-route: true # auto set global route for Windows
  # It is recommended to use `interface-name`
  auto-detect-interface: true # auto detect interface, conflict with `interface-name`
```
Finally, open the Clash

### Rules configuration
- Support rule `GEOSITE`.
- Support rule `USER-AGENT`.
- Support `multiport` condition for rule `SRC-PORT` and `DST-PORT`.
- Support `network` condition for all rules.
- Support `process` condition for all rules.
- Support source IPCIDR condition for all rules, just append to the end.

The `GEOIP` databases via [https://github.com/Loyalsoldier/geoip](https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb).

The `GEOSITE` databases via [https://github.com/Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat).
```yaml
rules:
  # network condition for all rules
  - DOMAIN-SUFFIX,example.com,DIRECT,tcp
  - DOMAIN-SUFFIX,example.com,REJECT,udp

  # process condition for all rules (add 'P:' prefix)
  - DOMAIN-SUFFIX,example.com,REJECT,P:Google Chrome Helper

  # multiport condition for rules SRC-PORT and DST-PORT
  - DST-PORT,123/136/137-139,DIRECT,udp

  # USER-AGENT payload cannot include the comma character, '*' meaning any character.
  - USER-AGENT,*example*,PROXY

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
Support outbound protocol `VLESS`.

Support `Trojan` with XTLS.

Support relay `UDP` traffic.

Currently XTLS only supports TCP transport.
```yaml
proxies:
  # VLESS
  - name: "vless-tls"
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    servername: example.com
    udp: true
    # skip-cert-verify: true
  - name: "vless-xtls"
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    servername: example.com
    flow: xtls-rprx-direct # or xtls-rprx-origin
    # flow-show: true # print the XTLS direction log
    # udp: true
    # skip-cert-verify: true

  # Trojan
  - name: "trojan-xtls"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    network: tcp
    flow: xtls-rprx-direct # or xtls-rprx-origin
    # flow-show: true # print the XTLS direction log
    # udp: true
    # sni: example.com # aka server name
    # skip-cert-verify: true

proxy-groups:
  # Relay chains the proxies. proxies shall not contain a relay.
  # Support relay UDP traffic.
  # Traffic: clash <-> ss1 <-> trojan <-> vmess <-> ss2 <-> Internet
  - name: "relay-udp-over-tcp"
    type: relay
    proxies:
      - ss1
      - trojan
      - vmess
      - ss2

  - name: "relay-raw-udp"
    type: relay
    proxies:
      - ss1
      - ss2
      - ss3
```

### IPTABLES configuration
Work on Linux OS who's supported `iptables`

```yaml
# Enable the TPROXY listener
tproxy-port: 9898

iptables:
  enable: true # default is false
  inbound-interface: eth0 # detect the inbound interface, default is 'lo'
```
Run Clash as a daemon.

Create the systemd configuration file at /etc/systemd/system/clash.service:
```sh
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
```sh
$ systemctl enable clash
```
Launch clashd immediately with:
```sh
$ systemctl start clash
```

### Display Process name
To display process name online by click [http://yacd.clash-plus.cf](http://yacd.clash-plus.cf) for local API by Safari or [https://yacd.clash-plus.cf](https://yacd.clash-plus.cf) for local API by Chrome.

You can download the [Dashboard](https://github.com/yaling888/yacd/archive/gh-pages.zip) into Clash home directory:
```sh
$ cd ~/.config/clash
$ curl -LJ https://github.com/yaling888/yacd/archive/gh-pages.zip -o yacd-gh-pages.zip
$ unzip yacd-gh-pages.zip
$ mv yacd-gh-pages dashboard
```

Add to config file:
```yaml
external-controller: 127.0.0.1:9090
external-ui: dashboard
```
Open [http://127.0.0.1:9090/ui/](http://127.0.0.1:9090/ui/) by web browser.

## Plus Pro Release
[Release](https://github.com/yaling888/clash/releases/tag/plus)

## Development
If you want to build an application that uses clash as a library, check out the the [GitHub Wiki](https://github.com/Dreamacro/clash/wiki/use-clash-as-a-library)

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)
