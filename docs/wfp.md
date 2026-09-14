# Windows WFP

`driver: wfp` 通过 WinDivert 2.2 接管本机其他进程的出站 TCP/UDP，使用 mihomo 的规则、代理和 DNS 处理。支持 Windows x86/x64，需管理员权限。

`stack: system` 使用 Windows TCP 协议栈并直接处理 UDP；`mixed` 使用 Windows TCP 协议栈和 gVisor UDP；`gvisor` 使用 gVisor 处理 TCP/UDP。

`system` 和 `mixed` 会为当前程序添加 TCP 入站防火墙规则，关闭监听器时移除。

```yaml
dns:
  enable: true
  nameserver:
    - 1.1.1.1
tun:
  enable: true
  driver: wfp
  stack: gvisor
  dns-hijack:
    - any:53
```

`mixed` 和 `gvisor` 构建时需要 `with_gvisor` 标签：

```powershell
go build -tags with_gvisor -o mihomo.exe .
```

省略 `driver` 时使用默认 TUN 驱动。

WFP 使用 `mtu`（默认 1500）、`dns-hijack`、`udp-timeout`（秒，默认 300）、`route-address`、`route-exclude-address`、`include-interface`、`exclude-interface`、`exclude-src-port` 和 `exclude-dst-port`。每个进程可启用一个 WFP 监听器。

`dns-hijack` 需要启用 `dns.enable`，支持普通 TCP/UDP DNS。IPv6 流量由全局 `ipv6` 和 `inet6-address` 控制；DNS 劫持可使用 IPv6 传输。

接管范围为目标地址属于全局单播、进程归属明确的完整 TCP/UDP 报文。TCP 接管从启用后的新连接开始；关闭监听器会解除拦截，已接管的 TCP 连接需要重新连接。

驱动和许可证位于 `component/windivert/driver`。嵌入的驱动会自动释放到运行账户 Local AppData 下的 `mihomo\windivert\2.2.2` 并加载。

管理员可运行三种协议栈的驱动集成测试：

```powershell
$env:MIHOMO_WFP_TEST = '1'
# 本机有 IPv6 出口时，可同时验证 2001:db8::1/128：
# $env:MIHOMO_WFP_TEST_IPV6 = '1'
go test -tags with_gvisor ./listener/sing_tun -run '^TestWFPIntegration$' -v -count=1 -timeout=90s
```
