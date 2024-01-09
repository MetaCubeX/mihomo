# http2ping for Clash.META

使用 HTTP2 Ping Frame 监测链路 rtt, 并从中选择 rtt 最优的链路

## 为什么

相比于`url-test`, http2ping 针对每个 endpoint 建立一条 HTTP2 长连接,
避免了频繁建立/断开连接,
因此我们可以使用更低的 interval(1s) 进行接近实时的 rtt 监测.

相比于使用`ICMP ping`进行延迟检测, 对于某些使用中转服务的网络接入供应商,
ICMP packets 只能检测`用户->中转->落地`这条链路的第一部分而非整条链路的完整 RTT.

相比于使用`http://www.gstatic.com/generate_204`这类常见的基于 HTTP 的 health check,
如果使用 HTTP 协议, 部分鸡贼的网络接入供应商会在中转服务器进行 MITM 直接返回 HTTP 204 response, 以试图欺骗客户.

## 配置

```YAML
# enable verbose logging for more infomation
log-level: debug
proxy-groups:
  - name: min-rtt-group
    type: http2-ping
    filter: "hk"
    use:
      - airport_1
    # interval milliseconds for sending Ping frame, default value: 1000ms
    interval: 1000
    # tolerance for changing current best route, default value: 0ms
    tolerance: 0
    # target server, default server: https://cloudflare.com
    server: https://cloudflare.com
```

## 测试

For debugging:

```bash
#!/bin/bash

interface=enp1s0
ip=1.1.1.1
delay=100ms

# add latency to ip address
tc qdisc add dev $interface root handle 1: prio
tc filter add dev $interface parent 1:0 protocol ip prio 1 u32 match ip dst $ip flowid 2:1
tc qdisc add dev $interface parent 1:1 handle 2: netem delay $delay

# remove tc rules
tc qdisc del dev $interface root
```