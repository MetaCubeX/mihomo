# Windows WFP

`intercept-mode: wfp` 通过 WinDivert 2.2 接管本机其他进程的出站 TCP/UDP，使用 mihomo 的规则、代理和 DNS 处理。支持 Windows x86/x64，需管理员权限。

```yaml
dns:
  enable: true
  nameserver:
    - 1.1.1.1
tun:
  enable: true
  intercept-mode: wfp
  stack: mips
  dns-hijack:
    - any:53
```

`stack` 可选 `system`（Windows TCP、直接处理 UDP）、`mixed`（Windows TCP、gVisor UDP）、`gvisor`（gVisor TCP/UDP）或 `mips`（MIPS TCP/UDP）。`system` 和 `mixed` 通过本机回环 TCP 中继转发连接。

`mixed` 和 `gvisor` 构建时需要 `with_gvisor` 标签：

```powershell
go build -tags with_gvisor -o mihomo.exe .
```

WFP 在现有网络接口上拦截流量。`intercept-mode` 默认值为 `vnic`，通过 TUN 虚拟网卡接管流量。

支持 `mtu`（1280–65535，默认 1500）、`dns-hijack`、`udp-timeout`（秒，默认 300）、`route-address`、`route-exclude-address`、`include-interface`、`exclude-interface`、`exclude-src-port`、`exclude-dst-port` 和对应的 `exclude-*-port-range`。端口范围格式为 `10000:11000`，包含两端。`auto-detect-interface` 跟踪默认出口接口。每个进程可启用一个 WFP 监听器。

地址、接口和端口条件决定内核拦截范围；编译后的过滤器最多包含 256 条指令，超出时需简化配置。`auto-route` 对 WFP 不生效。`gso`、`file-descriptor`、`auto-redirect`、`strict-route`、`loopback-address`、路由规则集以及 UID、Android 用户、包名、MAC 筛选不受支持。

`dns-hijack` 需要启用 `dns.enable`，支持 TCP/UDP DNS。IPv6 代理流量由全局 `ipv6` 和 `inet6-address` 控制；DNS 劫持可独立使用 IPv6 传输。

接管范围为目标地址属于全局单播、进程归属明确的完整 TCP/UDP 报文。当前进程、共享 UDP 端口归属有歧义的流量，以及 ICMP、分片、组播、链路本地和普通回环流量交由 Windows 处理。TCP 接管从启用后的新连接开始；关闭监听器后，已接管的 TCP 连接需要重新建立。

驱动和许可证位于 `component/windivert/driver`。嵌入的驱动会自动释放到运行账户 Local AppData 下的 `mihomo\windivert\2.2.2` 并加载。

运行单元测试：

```powershell
go test -tags with_gvisor ./component/windivert ./listener/sing_tun
```

管理员可运行驱动集成测试，覆盖四种协议栈的 TCP/UDP、DNS、过滤规则、接口监控和活动连接关闭。测试使用 `203.0.113.1` 作为拦截目标；具备到 `2001:db8::1` 的 IPv6 测试路径时，可设置 `MIHOMO_WFP_TEST_IPV6=1`，需要绑定源地址时设置 `MIHOMO_WFP_TEST_LOCAL_IPV6`。驱动测试应串行运行。

```powershell
$env:MIHOMO_WFP_TEST = '1'
go test -tags with_gvisor ./listener/sing_tun -run '^TestWFP(Integration|Policy|InterfaceMonitor|CloseActiveConnection)$' -v -count=1 -timeout=90s
```
