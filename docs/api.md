# mihomo REST API 参考

> 以源码为权威，列出 mihomo 内核 RESTful API 的全部路由、参数、响应、状态码与示例。内核：mihomo（MetaCubeX fork of clash-premium）。

---

## 1. 概览

### 1.1 文档覆盖范围

本文档覆盖 `hub/route/` 包注册的全部 HTTP / WebSocket endpoints，包括 network-policy 控制面的 `/network/context` endpoint。每个端点均给出：

- HTTP method 与 path
- 简介与典型用途
- path / query / header / body schema
- 响应 schema（含 WebSocket 帧格式）
- 涉及的 HTTP 状态码与错误体
- 一到两个 `curl` / `wscat` 示例

未覆盖：

- `hub/route/external.go` 是给上游嵌入方注册自定义路由的扩展点（`Register(externalRouter)`），mihomo 自身不调用。第三方注册的端点不在本文档范围内。
- `hub/route/patch_android.go` 仅含 Android 平台特定的运行时 patch，不增加端点。
- DoH endpoint（`hub/route/doh.go`）只有在 `external-doh-server` 配置了以 `/` 开头的路径时才会挂载，是 RFC 8484 标准接口而非 mihomo 控制面 API。本文档单独列出（见 §12.2）。

### 1.2 端点入口

`hub/route/server.go:router()` 同时把 router 服务到四个 transport：

| Transport | 配置字段 | Secret 鉴权 | CORS | UI | DoH |
|---|---|---|---|---|---|
| TCP HTTP | `external-controller` | 是 | 是 | 是 | 是 |
| TCP TLS | `external-controller-tls` + `external-controller-cert/key/ech-key/client-auth-*` | 是（共用同一 `secret`） | 是 | 是 | 是 |
| Unix socket | `external-controller-unix` | **否**（始终 secret="" 调用 router）| 是 | 是 | 是 |
| Windows Named Pipe | `external-controller-pipe`（必须以 `\\.\pipe\` 开头） | **否** | 是 | 是 | 是 |

> 三种 transport 共享 chi router 与 handler；区别只在监听层面与是否走鉴权 middleware。对应实现在 `hub/route/server.go:159` 起的 `start` / `startTLS` / `startUnix` / `startPipe`。

`/debug/*` 路由仅当启动时 `IsDebug=true`（命令行 `-d` 或配置层等价开关）才会挂载，且**不在已认证 group 中**——这是上游历史行为，文档照实记录。

`/restart`、`/configs PUT/PATCH/POST /geo`、`/upgrade`、`/upgrade/geo`、`/rules PATCH /disable` 在 `embedMode=true` 时被屏蔽（用于 SDK 嵌入场景，由调用方 `route.SetEmbedMode(true)` 开启）。

### 1.3 鉴权

`hub/route/server.go:327` 的 `authentication(secret)` middleware 检查每个 HTTP 请求：

- `Authorization: Bearer <secret>`：常规鉴权。`secret` 与配置 `secret` 字段做常量时间比较，失败返回 `401`。
- `Upgrade: websocket` + `?token=<secret>` query：浏览器 WebSocket 不支持自定义头，所以允许通过 query 参数携带 token；若提供则只校验 token，**忽略 Authorization 头**。
- 未提供 `Authorization`、且不是带 token 的 WebSocket 请求 → `401 Unauthorized`，body 为 `{"message":"Unauthorized"}`。
- 配置中 `secret == ""` 时，整个 `r.Group` 直接跳过 middleware，所有 endpoint 公开可访问。
- 通过 Unix socket / Named Pipe 访问时鉴权也被强制跳过（`startUnix` / `startPipe` 都是用 `secret=""` 调用 `router()`）。

`/debug/*` 端点未走 `authentication` middleware（位于 `r.Group` 之外）；如果开启 `IsDebug` 又同时绑定到非 loopback 地址，等同公开 pprof，请慎用。

### 1.4 跨域 CORS

由顶层 `r.Use(cors.New(...))` 应用到所有路由（`server.go:80`）：

- `Allowed-Methods`：`GET / POST / PUT / PATCH / DELETE`
- `Allowed-Headers`：`Content-Type / Authorization`
- `Max-Age`：`300` 秒
- 由配置 `external-controller-cors.allow-origins` 决定 `Allowed-Origins`；缺省为空列表。
- 由配置 `external-controller-cors.allow-private-network` 决定是否回写 `Access-Control-Allow-Private-Network: true`（Chrome 私网访问规范）。

CORS 中间件挂在最外层，因此所有 endpoint 都遵循同一规则。

### 1.5 响应与错误约定

所有 JSON 响应由 `github.com/metacubex/chi/render` 渲染，`Content-Type: application/json; charset=utf-8`。

错误响应有三种形态：

1. **`HTTPError`**：`{"message":"<reason>"}`。绝大多数 4xx / 5xx 走这一形态（`hub/route/errors.go`）。
2. **Network-policy envelope**：`{"code":"<short>","message":"<reason>"}`。仅 `/network/context` 三个 endpoint 使用，供 host sampler 做结构化错误分流——详见 §11.5。
3. **若干上游兼容的 `render.M`**：例如 `/restart`、`/upgrade*` 的成功响应是 `{"status":"ok"}`，`/version` / `/` 是平铺 map。
4. **DoH** 响应由 `render.PlainText` 输出 `text/plain; charset=utf-8` 或直接以 `application/dns-message` 写入二进制。

成功响应若不需要 body（如修改资源、关闭连接、删除 context），统一用 `render.NoContent` 返回 `204 No Content`。

mihomo 的状态码用法约定：

| 状态码 | 用途 |
|---|---|
| `200` | GET 成功，或 PUT/PATCH/POST 需要返回 body |
| `204` | PUT/PATCH/DELETE 成功且无 body |
| `400` | 请求体或参数非法（统一 `{"message":"Body invalid"}` 或携带具体原因） |
| `401` | 鉴权失败 |
| `404` | 资源不存在（多用于路径参数定位失败） |
| `405` | DoH endpoint 在 `wsUpgrade` 与 `dohHandler` 中分别可能产生 |
| `426` | WebSocket 升级时 `Sec-WebSocket-Version` 不为 `13` |
| `500` | 内部错误（DNS section 未启用、updater 失败、写盘失败等） |
| `503` | 服务暂不可用（代理 URLTest 失败、provider Update 失败、network-policy Manager 未就绪等） |
| `504` | URLTest 超时（`/proxies/{name}/delay`） |

### 1.6 路径中的 `{name}` 编码

代理名 / provider 名可能包含 `%`、`/`、空格等字符。`hub/route/common.go:21 getEscapeParam` 会对 chi 抓到的 path param 做 `url.PathUnescape`；调用方应对名字做 URL 编码（如 `/proxies/auto%20group`）。

### 1.7 WebSocket 升级

部分 endpoint（`/traffic` / `/memory` / `/logs` / `/connections`）支持把同一 GET 请求升级为 WebSocket 流：

- 客户端发 `Upgrade: websocket`、`Connection: Upgrade`、`Sec-WebSocket-Key: <24B base64>`、`Sec-WebSocket-Version: 13`，并通过 `Authorization: Bearer <secret>` **或** `?token=<secret>` 完成鉴权。
- 服务器响应 `101 Switching Protocols`，自此每个 tick（默认 1s）以 `OpText`（DNS 二进制 endpoint 除外）发送一个 JSON 序列化对象。
- 当 client 不发 `Upgrade: websocket` 时，相同的 endpoint 退化为 streaming HTTP（`Content-Type: application/json`，每个 tick `Flush` 一段 JSON）。**注意：流式 HTTP 和 WebSocket 共享同一 handler，行为一致，区别仅在帧封装。**
- 升级失败的 4xx/5xx 见 `wsUpgrade` 实现（`hub/route/common.go:33`）。

### 1.8 字段命名

mihomo 配置 YAML 使用 kebab-case；本文档涉及的 JSON request / response 字段大多为 camelCase（如 `socks-port`、`upTotal`、`startGo`），但部分较新 endpoint（`/network/context`、`/dns/query` 内部字段）使用 snake_case 与 mDNS 风格（`Status`、`Question`）。文档严格按源码字段标注。

---

## 2. 系统级 endpoints

### 2.1 `GET /`

返回静态欢迎信息，可用作健康检查。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/server.go:358` |

**响应**：`200 OK`

```json
{ "hello": "mihomo" }
```

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/
```

### 2.2 `GET /version`

返回内核名与版本号。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/server.go:563` |

**响应**：`200 OK`

```jsonc
{
  "meta": true,            // 始终 true（mihomo fork 标识）
  "version": "1.10.0"      // constant.Version；编译期常量
}
```

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/version
```

### 2.3 `GET /traffic`

返回**实时**流量与累计字节数。每秒推送一帧。

| 项目 | 值 |
|---|---|
| 鉴权 | 是（HTTP 头或 `?token=`） |
| 推送频率 | 1 秒/帧（`time.NewTicker(time.Second)`） |
| 协议 | streaming HTTP **或** WebSocket（取决于 `Upgrade` 头） |
| 来源 | `hub/route/server.go:362` |

**响应每帧 schema**：

```jsonc
{
  "up": 12345,         // 当前秒上传速率（bytes/s）
  "down": 67890,
  "upTotal": 1234567,  // 自启动以来累计字节
  "downTotal": 9876543
}
```

**HTTP 流式示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/traffic
```

**WebSocket 示例**：

```bash
wscat -c "ws://127.0.0.1:9090/traffic?token=<secret>"
```

### 2.4 `GET /memory`

返回内核进程 RSS 内存。**第一帧固定为 0**（兼容 chart.js 让曲线从 0 开始）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 推送频率 | 1 秒/帧 |
| 协议 | streaming HTTP 或 WebSocket |
| 来源 | `hub/route/server.go:408` |

**响应每帧 schema**：

```jsonc
{
  "inuse": 12345678,   // 进程 RSS 字节数
  "oslimit": 0          // 始终 0；保留字段
}
```

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/memory
```

### 2.5 `GET /logs`

订阅日志事件流。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 协议 | streaming HTTP 或 WebSocket |
| 来源 | `hub/route/server.go:473` |

**Query**：

| 名称 | 类型 | 说明 |
|---|---|---|
| `level` | enum | 默认 `info`。可选 `debug` / `info` / `warning` / `error` / `silent`，由 `log.LogLevelMapping` 决定。`silent` 等同关闭。无效值 → `400`。 |
| `format` | enum | 可选 `structured`；缺省时为兼容旧客户端的「平铺」格式。 |

**响应每帧 schema**：

- 默认（兼容形态）：

  ```jsonc
  {
    "type": "info",         // debug / info / warning / error
    "payload": "[TCP] connect to 1.2.3.4:443"
  }
  ```

- `format=structured`：

  ```jsonc
  {
    "time": "15:04:05",
    "level": "info",        // warning 被改写成 warn
    "message": "[TCP] ...",
    "fields": []
  }
  ```

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' "http://127.0.0.1:9090/logs?level=warning"
wscat -c "ws://127.0.0.1:9090/logs?level=debug&format=structured&token=<secret>"
```

---

## 3. Configs

### 3.1 `GET /configs`

返回当前生效的「General + Inbound」配置快照。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/configs.go:127` → `hub/executor/executor.go:141 GetGeneral` |

**响应** `200 OK`（字段对应 `config.General` / `config.Inbound`）：

```jsonc
{
  // Inbound 子结构（平铺）
  "port": 7890,
  "socks-port": 7891,
  "redir-port": 0,
  "tproxy-port": 0,
  "mixed-port": 0,
  "tun": { /* listener.GetTunConf() 的全部字段，结构见 LC.Tun */ },
  "tuic-server": { /* listener.GetTuicConf() 的全部字段 */ },
  "ss-config": "",
  "vmess-config": "",
  "authentication": ["user1:pwd1"],
  "skip-auth-prefixes": ["10.0.0.0/8"],
  "lan-allowed-ips": [],
  "lan-disallowed-ips": [],
  "allow-lan": false,
  "bind-address": "*",
  "inbound-tfo": false,
  "inbound-mptcp": false,

  // General 子结构
  "mode": "rule",                     // rule / global / direct
  "unified-delay": false,
  "log-level": "info",
  "ipv6": true,
  "interface-name": "",
  "routing-mark": 0,
  "geox-url": {
    "geo-ip": "https://...",
    "mmdb": "https://...",
    "asn": "https://...",
    "geo-site": "https://..."
  },
  "geo-auto-update": false,
  "geo-update-interval": 24,
  "geodata-mode": false,
  "geodata-loader": "memconservative",
  "geosite-matcher": "succinct",
  "tcp-concurrent": false,
  "find-process-mode": "off",         // off / strict / always
  "sniffing": false,
  "global-client-fingerprint": "",
  "global-ua": "mihomo/...",
  "etag-support": false,
  "keep-alive-idle": 30,
  "keep-alive-interval": 30,
  "disable-keep-alive": false
}
```

> `tun` 与 `tuic-server` 子对象字段较多且与平台相关，详细字段定义见 `listener/config/tun.go` 与 `listener/config/tuic.go`，本文档不展开。

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/configs
```

### 3.2 `PATCH /configs`

**部分**热修改运行时配置（仅在 `embedMode=false` 时挂载）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/configs.go:312` |

**Body**：所有字段均为可选；只发送想要修改的字段：

```jsonc
{
  "port": 7890,
  "socks-port": 7891,
  "redir-port": 7892,
  "tproxy-port": 0,
  "mixed-port": 0,
  "tun": { /* 同 GET /configs.tun，字段全部可选 */ },
  "tuic-server": { /* 同 GET /configs.tuic-server */ },
  "ss-config": "ss://...",
  "vmess-config": "...",
  "tcptun-config": "1.1.1.1:443",      // 仅对 PATCH 有效；GET 不返回
  "udptun-config": "1.1.1.1:443",      // 仅对 PATCH 有效；GET 不返回
  "allow-lan": true,
  "skip-auth-prefixes": ["10.0.0.0/8"],
  "lan-allowed-ips": ["192.168.1.0/24"],
  "lan-disallowed-ips": [],
  "bind-address": "*",
  "mode": "rule",
  "log-level": "warning",
  "ipv6": true,
  "sniffing": true,
  "tcp-concurrent": true,
  "find-process-mode": "strict",
  "interface-name": "en0"
}
```

字段说明：

- 监听端口字段会触发对应监听器的 `ReCreateXxx` —— 端口为 0 视作关闭。
- `mode`、`log-level`、`find-process-mode` 是 enum，传非法值会被对应 setter 接受/拒绝（不在 handler 层校验）。
- `interface-name` 为空字符串等同 `""`，意味着不绑定具体接口。
- 未列出字段（如 `tls.*`、`dns.*`）此 endpoint 不支持，需要通过 `PUT /configs` 整体重载。

**响应**：`204 No Content`。

JSON body 解析失败 → `400` + `{"message":"Body invalid"}`。

**示例**：

```bash
curl -X PATCH \
     -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     -d '{"mode":"global","log-level":"debug"}' \
     http://127.0.0.1:9090/configs
```

### 3.3 `PUT /configs`

**完整**重载配置（仅在 `embedMode=false` 时挂载）。等同重新解析一份 YAML 并 ApplyConfig。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/configs.go:383` |

**Query**：

| 名称 | 类型 | 说明 |
|---|---|---|
| `force` | bool | `true` → 即使 listener 配置未变也强制重建监听器；缺省 `false`。 |

**Body**：二选一 ——

```jsonc
{ "payload": "<完整 YAML 字符串>" }
// 或
{ "path": "/abs/path/to/config.yaml" }
// 都不填则使用默认配置文件路径（C.Path.Config()）
```

**约束**：

- `path` 必须是绝对路径，否则 `400 invalid`：`{"message":"path is not a absolute path"}`。
- `path` 必须落在 `C.Path.IsSafePath` 允许的目录内（默认是配置目录），否则 `400`。
- `payload` 不为空时 `path` 字段被忽略。
- YAML 解析失败 → `400` + 解析错误原文。

**响应**：

- `204 No Content`：成功。
- `400`：请求体非法或 YAML 解析失败。

**示例**：

```bash
# 通过 path
curl -X PUT \
     -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     -d '{"path":"/etc/mihomo/config.yaml"}' \
     "http://127.0.0.1:9090/configs?force=true"

# 通过 payload
curl -X PUT \
     -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     --data-binary @config.json \
     http://127.0.0.1:9090/configs
```

### 3.4 `POST /configs/geo`

主动触发 GeoIP / GeoSite / MMDB / ASN 数据库更新（仅在 `embedMode=false` 时挂载）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/configs.go:434` |

**响应**：

- `204 No Content`：更新成功。
- `500`：updater 失败 → `{"message":"<reason>"}`。

**示例**：

```bash
curl -X POST -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/configs/geo
```

> 与 `POST /upgrade/geo` 等价（同一 handler，见 §9.3）。

---

## 4. Proxies

代理对象包括：单个 outbound（DIRECT/REJECT/Trojan/Shadowsocks/...）、Selector、Fallback、URLTest、Relay、LoadBalance 等。所有这些都通过 `/proxies` 暴露；只有「proxy group」（具备 `outboundgroup.ProxyGroup` 接口的 Selector / Fallback / URLTest / LoadBalance / Relay 等）也会出现在 `/group` 下。

### 4.1 `GET /proxies`

返回所有 proxy（单 proxy + 组）的合集 map，**包括从所有 ProxyProvider 中展开的 proxy**。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/proxies.go` 的 `getProxies` 函数 |

**响应**：`200 OK`

```jsonc
{
  "proxies": {
    "GLOBAL": {
      "type": "Selector",
      "now": "auto",
      "all": ["DIRECT", "REJECT", "auto", "hk-1", "us-1"],
      "testUrl": "",
      "hidden": false,
      "icon": "",
      "history": [{ "time": "2025-04-19T12:00:00Z", "delay": 50 }],
      "extra": { /* map[string]map[string]any 形式的额外测速结果 */ },
      "alive": true,
      "name": "GLOBAL",
      "udp": true,
      "uot": false,
      "xudp": false,
      "tfo": false,
      "mptcp": false,
      "smux": false,
      "interface": "",
      "routing-mark": 0,
      "provider-name": "",
      "dialer-proxy": ""
    },
    "DIRECT": { "type": "Direct", "id": "...", "history": [], "alive": true, ... },
    ...
  }
}
```

字段来源：

- `adapter.Proxy.MarshalJSON`（`adapter/adapter.go:135`）注入 `history` / `extra` / `alive` / `name` / `udp` / `uot` / `xudp` / `tfo` / `mptcp` / `smux` / `interface` / `routing-mark` / `provider-name` / `dialer-proxy`。
- 单 proxy 的 `Base.MarshalJSON`（`adapter/outbound/base.go:99`）只输出 `type` / `id`。
- 组类型的 MarshalJSON 增加 `now` / `all` / `testUrl` / `hidden` / `icon`，Fallback/URLTest 还增加 `expectedStatus` / `fixed`。

> `proxiesWithProviders` 函数已被标记 deprecated（`hub/route/proxies.go` 的 `proxiesWithProviders`），但保留以维持现有 API 输出兼容性。

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

### 4.2 `GET /proxies/{name}`

返回单个 proxy 的详情（即上面 `proxies` map 中名为 `name` 的那个值）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/proxies.go` 的 `getProxy` 函数 |

**Path**：`{name}` 经 `url.PathUnescape` 解码。

**响应**：`200 OK` + 同 §4.1 的单个 proxy 对象，或 `404 Not Found`。

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies/GLOBAL
```

### 4.3 `PUT /proxies/{name}`

切换 Selector / Fallback / URLTest 等可手动选择组的当前选择。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/proxies.go` 的 `updateProxy` 函数 |

**Body**：

```jsonc
{ "name": "hk-1" }
```

**行为**：

- Handler 委托 `networkpolicy.Default().ManualSet(proxy, req.Name)`，由 Manager 统一处理 selectable/selectorWithPolicy 分派、cachefile 写入与 manual-wins 钩子。带 `network-policy` 的 Selector 额外写 `bucketNetworkPolicy`（source=manual）。
- 错误通过 `errors.Is` 分级：`ErrManagerNotInitialized` → `503`；`ErrNotSelectable` / `ErrProxyNotExist` → `400`；其他未归类 error → `500` 并 `log.Warnln`。
- 成功后异步触发 `SwitchProxiesCallback`（若注册），再返回 `204 No Content`。自动切换路径（`PutContext` 等）**不**触发 callback，避免 UI flicker。

**响应**：

| 状态 | body |
|---|---|
| `204 No Content` | 切换成功 |
| `400` | body 不是合法 JSON / group 非 selectable / target 不在候选 |
| `404` | path 上的 `name` 不存在 |
| `503` | `{"message":"network-policy manager not initialized"}`（启动窗口） |

**示例**：

```bash
curl -X PUT \
     -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     -d '{"name":"hk-1"}' \
     http://127.0.0.1:9090/proxies/auto
```

### 4.4 `DELETE /proxies/{name}`

清除 Selector 之外的可选择组（Fallback / URLTest / LoadBalance）的「fixed」状态——让它回到自动选择。Selector 类型不允许 unfix（`unfixedProxy` 显式过滤）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/proxies.go` 的 `unfixedProxy` 函数 |

**响应**：

| 状态 | body |
|---|---|
| `204 No Content` | 清除成功 |
| `400` | 该 proxy 不是 SelectAble，或者它是 Selector 类型 |
| `404` | name 不存在 |

**示例**：

```bash
curl -X DELETE \
     -H 'Authorization: Bearer <secret>' \
     http://127.0.0.1:9090/proxies/auto
```

### 4.5 `GET /proxies/{name}/delay`

对单个 proxy 做一次 URLTest，返回当前延迟。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/proxies.go` 的 `getProxyDelay` 函数 |

**Query**：

| 名称 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `url` | string | 是 | 测试 URL，例如 `https://www.gstatic.com/generate_204` |
| `timeout` | int | 是 | 超时毫秒数（int16 范围）；非数字 → `400` |
| `expected` | string | 否 | HTTP status code 范围，例如 `204` / `200-299` / `200/204/301-302`；非法 → `400`。空表示不限制。 |

**响应**：

| 状态 | body |
|---|---|
| `200 OK` | `{"delay": 123}`（毫秒） |
| `400` | query 缺失或非法 |
| `503` | 测试失败但未超时（`{"message":"<原因>"}`） |
| `504` | 超时（`{"message":"Timeout"}`） |

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' \
     "http://127.0.0.1:9090/proxies/hk-1/delay?url=https://www.gstatic.com/generate_204&timeout=3000&expected=204"
```

---

## 5. Proxy Groups

> 注：`/group` 与 `/proxies` 共享 proxy 实例集合，但 `/group` 只暴露具备 `ProxyGroup` 接口的对象（Selector / URLTest / Fallback / LoadBalance / Relay）。

### 5.1 `GET /group`

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/groups.go:31` |

**响应**：`200 OK`

```jsonc
{
  "proxies": [ /* 数组，元素 schema 同 §4.1 中的组对象 */ ]
}
```

> 与 `/proxies` 不同的是，这里只来自 `tunnel.Proxies()`（即顶层声明的组），**不**包含 provider 内的 proxies；同时是数组而非 map。

### 5.2 `GET /group/{name}`

返回单个组对象。若 `name` 不存在或不是组 → `404`。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/groups.go:43` |

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/group/auto
```

### 5.3 `GET /group/{name}/delay`

对一个组内**所有**候选并发跑 URLTest，返回 `map[proxyName]delayMs`。

副作用：调用前会对**非 Selector 类型**的 SelectAble 组执行 `ForceSet("")` + `cachefile.SetSelected(name, "")`，等同于自动模式重置 fixed 状态。Selector 不重置。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/groups.go:53` |

**Query**：同 §4.5（`url` / `timeout` / `expected`）。

**响应**：

| 状态 | body |
|---|---|
| `200 OK` | `{ "hk-1": 123, "hk-2": 0, ... }`（0 通常表示该 proxy 失败） |
| `400` | query 非法 |
| `404` | `name` 不是组 |
| `504` | URLTest 整体失败（`{"message":"<context deadline exceeded ...>"}`） |

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' \
     "http://127.0.0.1:9090/group/auto/delay?url=https://www.gstatic.com/generate_204&timeout=3000"
```

---

## 6. Rules

### 6.1 `GET /rules`

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/rules.go:42` |

**响应**：`200 OK`

```jsonc
{
  "rules": [
    {
      "index": 0,
      "type": "DOMAIN",
      "payload": "google.com",
      "proxy": "auto",
      "size": -1,                     // 仅 GEOIP / GEOSITE 给出包含数；其他类型为 -1
      "extra": {                      // 仅当 rule 已被 RuleWrapper 包装时出现
        "disabled": false,
        "hitCount": 12,
        "hitAt": "2025-04-19T11:59:00Z",
        "missCount": 3,
        "missAt": "2025-04-19T11:58:30Z"
      }
    }
  ]
}
```

字段来源：

- `Rule.Type` / `Rule.Payload` / `Rule.Adapter` 来自规则解析。
- `Extra` 与 `RuleWrapper`（`constant/rule.go`）相关，统计 hit / miss。

### 6.2 `PATCH /rules/disable`

按 index 启用/停用一组规则（仅 `embedMode=false` 时挂载，需要 `RuleWrapper`，否则忽略）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/rules.go:76` |

**Body**：`map[int]bool`，key = rule index（同 `GET /rules` 返回的 `index`），value = 是否禁用。

```jsonc
{ "0": true, "5": false, "12": true }
```

非法 index 被静默忽略；JSON 解析失败 → `400`。

**响应**：`204 No Content`。

**示例**：

```bash
curl -X PATCH \
     -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     -d '{"3":true,"4":true}' \
     http://127.0.0.1:9090/rules/disable
```

---

## 7. Providers

### 7.1 Proxy Providers

#### 7.1.1 `GET /providers/proxies`

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:40` |

**响应**：`200 OK`

```jsonc
{
  "providers": {
    "ProviderA": {
      "name": "ProviderA",
      "type": "Proxy",                 // adapter/provider.providerForApi.Type
      "vehicleType": "HTTP",           // HTTP / File / Compatible / Inline
      "proxies": [ /* 同 §4.1 中的 proxy 对象 */ ],
      "testUrl": "https://www.gstatic.com/generate_204",
      "expectedStatus": "204",
      "updatedAt": "2025-04-19T11:30:00Z",
      "subscriptionInfo": {            // 可选；存在时是订阅协议解析出的流量信息
        "Upload": 0, "Download": 0, "Total": 0, "Expire": 0
      }
    }
  }
}
```

字段来源：`adapter/provider/provider.go:34 providerForApi`。

- `compatibleProvider` 不返回 `updatedAt` / `subscriptionInfo` 字段（`omitempty`）。
- `inlineProvider` 不返回 `subscriptionInfo`。

#### 7.1.2 `GET /providers/proxies/{providerName}`

返回单个 proxy provider 的详情。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:47` |

**响应**：`200 OK` + 同上 schema 中单个 provider 对象，或 `404`。

#### 7.1.3 `PUT /providers/proxies/{providerName}`

强制刷新一个 proxy provider（重新拉取订阅）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:52` |

**响应**：

| 状态 | body |
|---|---|
| `204 No Content` | 刷新成功 |
| `404` | `providerName` 不存在 |
| `503` | provider 内部 `Update()` 报错（`{"message":"<原因>"}`） |

#### 7.1.4 `GET /providers/proxies/{providerName}/healthcheck`

触发整个 provider 的健康检查（异步并发跑 URLTest），endpoint 立即返回。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:62` |

**响应**：`204 No Content`。

#### 7.1.5 `GET /providers/proxies/{providerName}/{name}`

返回该 provider 中名为 `name` 的单个 proxy 对象（同 §4.2 schema）。`404` 当 provider 或 proxy 不存在。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:32` 子路由（`getProxy` handler 复用） |

#### 7.1.6 `GET /providers/proxies/{providerName}/{name}/healthcheck`

对该 provider 中的单个 proxy 做一次 URLTest 并返回延迟。`Query` 与响应同 §4.5（注意：尽管路径叫 `/healthcheck`，handler 复用的是 `getProxyDelay`，所以 `url` / `timeout` / `expected` 仍然是必传 query）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:35` |

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' \
     "http://127.0.0.1:9090/providers/proxies/ProviderA/hk-1/healthcheck?url=https://www.gstatic.com/generate_204&timeout=3000"
```

### 7.2 Rule Providers

#### 7.2.1 `GET /providers/rules`

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:123` |

**响应**：`200 OK`

```jsonc
{
  "providers": {
    "MyRules": {
      "behavior": "domain",          // domain / ipcidr / classical
      "format": "yaml",              // yaml / text / mrs；inline 不返回此字段
      "name": "MyRules",
      "ruleCount": 1234,
      "type": "Rule",
      "vehicleType": "HTTP",         // HTTP / File / Inline
      "updatedAt": "2025-04-19T10:00:00Z",
      "payload": ["+.example.com"]   // 仅 inline provider 携带
    }
  }
}
```

字段来源：`rules/provider/provider.go:35 providerForApi`。

#### 7.2.2 `PUT /providers/rules/{name}`

强制刷新一个 rule provider。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/provider.go:130` |

**响应**：

| 状态 | body |
|---|---|
| `204 No Content` | 成功 |
| `404` | `name` 不存在 |
| `503` | `provider.Update()` 失败（`{"message":"<原因>"}`） |

---

## 8. Connections

### 8.1 `GET /connections`

返回当前活跃连接快照；若以 WebSocket 升级则按 `interval` 周期推送。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 协议 | 单次 HTTP GET **或** WebSocket |
| 来源 | `hub/route/connections.go:24` |

**Query**（仅 WebSocket 模式生效）：

| 名称 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `interval` | int (ms) | `1000` | 每帧间隔；非数字 → `400` |

**响应 schema**：

```jsonc
{
  "downloadTotal": 1234567,   // statistic.Manager 累计字节
  "uploadTotal":   2345678,
  "memory": 12345678,         // 进程 RSS（与 /memory 同源）
  "connections": [
    {
      "id": "f3b5...uuid",
      "metadata": {
        "network": "tcp",          // tcp / udp
        "type": "HTTP",            // SOCKS / HTTP / Mixed / Tun / ...
        "sourceIP": "192.168.1.10",
        "destinationIP": "1.2.3.4",
        "sourceGeoIP": ["CN"],     // null = 未查询；[] = 查询无结果
        "destinationGeoIP": ["US"],
        "sourceIPASN": "AS123",
        "destinationIPASN": "AS456",
        "sourcePort":      "55672",  // 注意是字符串（兼容旧版 JSON）
        "destinationPort": "443",    // 注意是字符串
        "inboundIP":       "127.0.0.1",
        "inboundPort":     "7890",
        "inboundName":     "DEFAULT-HTTP",
        "inboundUser":     "",
        "host": "www.example.com",
        "dnsMode": "fake-ip",
        "uid": 501,
        "process": "curl",
        "processPath": "/usr/bin/curl",
        "specialProxy": "",
        "specialRules": "",
        "remoteDestination": "1.2.3.4:443",
        "dscp": 0,
        "sniffHost": "www.example.com"
      },
      "upload": 1234,
      "download": 5678,
      "start": "2025-04-19T11:00:00Z",
      "chains": ["DIRECT"],            // 反向；末尾是最贴近 outbound 的代理
      "providerChains": [],
      "rule": "DOMAIN",
      "rulePayload": "example.com"
    }
  ]
}
```

> `metadata` 字段对应 `constant/metadata.go:180 Metadata`。注意 `sourcePort` / `destinationPort` / `inboundPort` 出于历史兼容性是字符串。

**HTTP 单次示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/connections
```

**WebSocket 周期推送**：

```bash
wscat -c "ws://127.0.0.1:9090/connections?interval=2000&token=<secret>"
```

### 8.2 `DELETE /connections`

立即关闭所有活跃连接。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/connections.go:81` |

**响应**：`204 No Content`。

### 8.3 `DELETE /connections/{id}`

按 UUID 关闭单个连接；找不到 ID 则**静默成功**。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/connections.go:73` |

**响应**：`204 No Content`。

**示例**：

```bash
curl -X DELETE -H 'Authorization: Bearer <secret>' \
     http://127.0.0.1:9090/connections/f3b50000-...
```

---

## 9. Cache / DNS / GEO

### 9.1 `POST /cache/fakeip/flush`

清空 Fake-IP 池。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/cache.go:18` |

**响应**：

| 状态 | body |
|---|---|
| `204 No Content` | 清空成功 |
| `400` | `resolver.FlushFakeIP` 失败（如 Fake-IP 未启用），`{"message":"<原因>"}` |

### 9.2 `POST /cache/dns/flush`

清空 DNS 解析缓存。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/cache.go:28` |

**响应**：`204 No Content`。

### 9.3 `GET /dns/query`

通过 mihomo 内置 resolver 做 DNS 查询，返回 Google DoH 风格的 JSON。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/dns.go:22` |

**Query**：

| 名称 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `name` | string | — | 待查询域名（自动追加 `.`） |
| `type` | string | `A` | DNS RR 类型（`A` / `AAAA` / `CNAME` / `TXT` / `MX` / ...，依据 `dns.StringToType`） |

**响应** `200 OK`：

```jsonc
{
  "Status": 0,                // dns.Rcode
  "Question": [{ "Name": "example.com.", "Qtype": 1, "Qclass": 1 }],
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Answer": [
    { "name": "example.com.", "type": 1, "TTL": 60, "data": "93.184.216.34" }
  ],
  "Authority": [...],         // 可选
  "Additional": [...]         // 可选
}
```

**错误**：

| 状态 | body |
|---|---|
| `400` | `type` 非法 → `{"message":"invalid query type"}` |
| `500` | DNS section 未启用 → `{"message":"DNS section is disabled"}` |
| `500` | 解析失败 → `{"message":"<resolver error>"}` |

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' \
     "http://127.0.0.1:9090/dns/query?name=example.com&type=AAAA"
```

### 9.4 `POST /upgrade/geo`

等同 `POST /configs/geo`（同一 `updateGeoDatabases` handler；仅 `embedMode=false`）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/upgrade.go:21` → `hub/route/configs.go:434` |

### 9.5 `GET /storage/{key}` / `PUT /storage/{key}` / `DELETE /storage/{key}`

通用 JSON key-value 存储，后端是 `component/profile/cachefile` bucket（与 `selected` / `bucketNetworkPolicy` 共用同一 bbolt 文件但独立 bucket）。供宿主持久化任意 UI 状态、偏好、缓存等——mihomo 不解析 value。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/storage.go` |

`GET /storage/{key}`：

- 200 + `application/json`，body 为 `PUT` 时存入的 JSON 原样；不存在则返回 `null`（200）。

`PUT /storage/{key}`：

- body 必须是合法 JSON（任意类型：object / array / string / number / bool / null），非法 → `400 {"message":"Body invalid"}`。
- 上限 `1 MiB`，超限 → `413 {"message":"payload exceeds 1MB limit"}`。
- 成功 → `204 No Content`；写盘与否受 `store-selected` 的 cachefile 启用状态影响（写入始终发生；读取由 cachefile 层管理持久化）。

`DELETE /storage/{key}`：

- 幂等；key 不存在也返回 `204`。

`{key}` 支持 URL-encoded 字符（调用方编码，服务端 `url.PathUnescape`），空字符串 key 不推荐但不特殊处理。

**示例**：

```bash
curl -X PUT -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     -d '{"ui_theme":"dark","collapsed":["home"]}' \
     http://127.0.0.1:9090/storage/cvr-ui-state

curl -H 'Authorization: Bearer <secret>' \
     http://127.0.0.1:9090/storage/cvr-ui-state
# → {"ui_theme":"dark","collapsed":["home"]}

curl -X DELETE -H 'Authorization: Bearer <secret>' \
     http://127.0.0.1:9090/storage/cvr-ui-state
```

---

## 10. Lifecycle / Upgrade

### 10.1 `POST /restart`

冷重启内核进程（仅 `embedMode=false`）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/restart.go:24` |

**行为**：

1. 立即 `render.JSON(w, r, {"status":"ok"})` 并 Flush。
2. 调用 `executor.Shutdown()` 优雅关闭后，在 Windows 用 `exec.Command(...).Start()` + `os.Exit(0)`，在 Unix 用 `syscall.Exec` 替换映像。

**响应**：

| 状态 | body |
|---|---|
| `200 OK` | `{"status":"ok"}`（成功安排重启） |
| `500` | 拿不到自己的 executable 路径 → `{"message":"getting path: <reason>"}` |

> 注意：成功响应是 `200 + body`，**不是** `204`。

### 10.2 `POST /upgrade`

升级内核到最新发布版（仅 `embedMode=false`）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/upgrade.go:25` |

**Query**：

| 名称 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `channel` | string | `""`（即 release） | 传给 `updater.DefaultCoreUpdater.Update`；可选 `Alpha`、`Prerelease` 等，由 updater 实现决定 |
| `force` | bool | `false` | 跳过版本对比直接覆盖 |

**响应**：

| 状态 | body |
|---|---|
| `200 OK` | `{"status":"ok"}`，随后异步触发 `restartExecutable` |
| `500` | 拿不到 executable 路径 / updater 失败 → `{"message":"<原因>"}` |

**示例**：

```bash
curl -X POST -H 'Authorization: Bearer <secret>' \
     "http://127.0.0.1:9090/upgrade?channel=alpha&force=true"
```

### 10.3 `POST /upgrade/ui`

下载 / 更新外置 UI 包（不受 `embedMode` 限制）。

| 项目 | 值 |
|---|---|
| 鉴权 | 是 |
| 来源 | `hub/route/upgrade.go:55` |

**响应**：

| 状态 | body |
|---|---|
| `200 OK` | `{"status":"ok"}` |
| `500` | UI updater 失败 → `{"message":"<原因>"}` |

> 真正的 UI 静态资源由 `external-ui` 配置项决定的目录服务，挂载点见 §12.1。

---

## 11. Network Policy

> handler 位于 `hub/route/network.go`，状态机位于 `component/networkpolicy/manager.go`，通过 `networkpolicy.Global()` 对外提供 singleton。`select` 代理组根据宿主实时推送的"当前处于哪些网络"自动切换代理，同时允许用户手动选择在同一 network 下粘滞。

### 11.0 通用约定

- 路径全部挂在 `/network/context`（单数；REST 资源单实例多动词）。
- 鉴权：复用 external-controller `secret`，与 `/proxies` 等同。
- Manager 未初始化（`ApplyConfig` 启动期毫秒级窗口，或配置未包含 `networks:`）→ `PUT` 返回 `503 Service Unavailable` + `{"code":"internal_error","message":"network-policy manager not yet initialized"}`；`GET` 退化为"无 context"响应（`context`/`matched_network`/`expires_at`/`age_seconds` 均 `null`，`groups: []`）；`DELETE` no-op 仍返回 `204`。
- JSON 字段命名：PUT / GET body 均用 snake_case；对应 `networks:` / `network-policy:` YAML 使用 kebab-case（两侧由归一化对齐）。
- `version` 字段必填，固定为 `1`；缺失 → `malformed_body`，其它值 → `invalid_version`。
- **未知顶层字段**：kernel 宽容忽略（用 Go `json.Unmarshal` 默认行为），便于后续 additive 扩展；host 侧 PUT body schema 对未知字段忽略以利 forward-compat，YAML matcher 对未知 key `fail-fast` 以利配置防呆。
- 缺失字段 = "未知"，不等于 "false / 空串"；`metered` 是 tri-state（`null` / `true` / `false`）。
- **错误响应包络**（`/network/context` 专用，与其它 endpoint 的 `{"message":"..."}` 不同）：

  ```jsonc
  {
    "code": "<short_identifier>",
    "message": "<human readable>"
  }
  ```

  host 按 `code` 做结构化分流，`invalid_field` 的 `message` 遵循 `field: <path>, reason: <why>` 约定。完整 code 表见 §11.5。

- 归一化规则（`NormalizeAndValidate` 在 PUT 入口执行；GET 回显的 `context` 是归一化后副本）：
  - `dns_suffix[]`：每项 `strings.ToLower` → 去空字符串 → 字典序排序 → 去重；**不做** trim，每项禁止包含逗号 / 空白 / 控制字符（违反 → `invalid_field`）。
  - `interfaces[].iface_type`：小写；非枚举值 → `invalid_field`。
  - `interfaces[].bssid` / `interfaces[].gateway_mac`：归一化为小写冒号分隔；非法 MAC → `invalid_field`。
  - `interfaces[].gateway_ip`：`netip.ParseAddr`；IPv6 strip zone。
  - `interfaces[].subnets[]`：`netip.ParsePrefix` + `Masked()` + IPv6 strip zone → 字符串序排序 + 去重。
  - `interfaces[].ssid`：**不**做归一化（IEEE 802.11 octet string 语义，大小写敏感）。
- 硬上限：`interfaces.len() ≤ 32`（`MaxInterfaces`），超限 → `too_many_interfaces`。
- TTL 单位秒，**最大 10 年（`315_360_000`）**，超过或 `<= 0` → `invalid_ttl`；省略 = sticky（不自动过期）；想立即清除请用 DELETE。
- PUT body 大小上限 10 MiB（`http.MaxBytesReader`）——是 DoS 防护，非 wire 契约；正常 body 离此上限很远。

### 11.1 `PUT /network/context`

把宿主采集到的当前活跃接口集合推给内核，触发状态机评估并切换带 `network-policy` 的 `select` 组。

**Body**（`NetworkContext`，对应 `component/networkpolicy/context.go`）：

```jsonc
{
  "version": 1,                              // 必填；固定为 1
  "interfaces": [                            // 必填；可为空数组（"离线"时走 default 兜底）
    {
      "name": "wlan0",                       // 必填；集合内唯一；≤ 255 字节
      "iface_type": "wifi",                  // wifi | ethernet | cellular | wwan | vpn | loopback | other
      "ssid": "office-5g",                   // ≤ 32 字节；大小写敏感
      "bssid": "aa:bb:cc:dd:ee:00",          // 归一化为小写冒号
      "gateway_ip": "10.0.0.1",              // iff sampler 判定该 iface 为默认路由候选
      "gateway_mac": "11:22:33:44:55:66",    // 仅在 gateway_ip 填充时才能填
      "subnets": ["10.0.0.0/24"],            // iface 本地地址前缀
      "metered": false                       // tri-state null / true / false
    },
    {
      "name": "wg0",
      "iface_type": "vpn"
    }
  ],
  "dns_suffix": ["corp.example.com"],        // 顶层全局；数组；允许 null / 省略（视作空数组）；scalar 被拒
  "ttl": 1800                                // 可选；秒；省略 = sticky；≤ 0 或 > 10 年 → invalid_ttl
}
```

**关键点**：

- `interfaces[]` 有 32 张上限；`name` 必须集合内唯一；重复 → `duplicate_iface_name`。
- `gateway_mac` 非空但 `gateway_ip` 空 → `invalid_gateway_combo`（反向允许）。
- `dns_suffix` **不绑定**任何 iface，始终对应顶层系统 DNS search list；matcher `dns-suffix:` 始终映射到这个全局值。
- `subnets` 只含接口本地地址前缀（`getifaddrs` 级），**不含**路由表 next-hop（例如 WireGuard `AllowedIPs` 不出现在 `subnets`）。
- 不含 `primary_iface` / `is_primary`：单接口选择权完全由 `networks:` 列表顺序 first-match 决定。

**响应** `200 OK`：

```jsonc
{
  "matched_network": "office",               // 命中 first-match 的 network name；未命中（内部 <none>）或无 ctx → JSON null
  "applied": [                               // 每个带 network-policy 的 select 组各一项，按 YAML 声明顺序
    {
      "group": "auto",
      "target_proxy": "hk",                  // policy 决策目标；可为 null
      "applied_proxy": "hk",                 // 本轮应用后的当前代理（始终非 null）
      "changed": true,                       // 本次是否真的调用了 selector.Set()
      "selection_source": "auto",            // auto | manual | unknown
      "reason": "matched"                    // 见下方枚举
    }
  ],
  "expires_at": 1713401800                   // sticky 时为 null
}
```

**`reason` 七种枚举**（与 `component/networkpolicy/policy.go` 的 `ReasonXxx` 常量 1:1）：

| reason | 触发条件 | 是否更新 `last_matched_network` |
|---|---|---|
| `matched` | Match 命中 N，Mapping[N] 有 target，已成功 Set | 是（设为 N） |
| `already_selected` | 同 `matched`，但 target 等于当前选择，未调 Set | 是（设为 N） |
| `default` | Match 未命中 / 命中但 Mapping 无 target；policy 有 `default` 且 target 在候选中 → 切到 default | 是（命中为 N，未命中为 `<none>`） |
| `no_change_no_default` | 同 `default` 左半触发条件，但 policy **无** `default` → 保持当前选择，source 仍重置为 auto | 是 |
| `unchanged_network` | matched（含 `<none>`）与本组 `last_matched_network` 相同且 `source == auto` → 跳过评估 | 否 |
| `manual_locked` | matched（含 `<none>`）与本组 `last_matched_network` 相同且 `source == manual` → 尊重手动选择 | 否 |
| `missing_target` | policy 求得非空 target 但不在本组当前候选（provider 缺失）→ 跳过切换；source / last_matched 不变 | 否 |

**手动 / 自动状态机（manual-wins）**：

1. 用户手动 `PUT /proxies/:name` → 该组 `selection_source = manual`；`last_matched_network` 不变。
2. 下次 `PUT /network/context`：
   - matched 未变 + `source=manual` → `manual_locked`。
   - matched 变了且评估落入 `matched` / `already_selected` / `default` / `no_change_no_default` → auto 流程接管，`source` 重置为 `auto`，`last_matched` 前进。
   - matched 变了但评估落入 `missing_target`（target 暂不可达）→ source / last_matched 都保留，等下次 PUT 重试。

**TTL 轻量路径**（§5.6.3）：当以下五个条件全部满足时，PUT 不进 manager 串行队列、不重评估、不写 cachefile，只刷新 `expires_at`：
(a) 归一化后 ctx fingerprint 与缓存相同；(b) 本次 body 带 `ttl`；(c) 缓存 ctx 已带 `ttl`；(d) 无任何组处于 `missing_target` 待重试；(e) 自上次评估以来候选集未变（provider 未 refresh）。其它所有情况走完整评估路径。

**错误响应**：见 §11.5 code 表。

**示例**：

```bash
curl -X PUT \
     -H 'Authorization: Bearer <secret>' \
     -H 'Content-Type: application/json' \
     -d '{
           "version": 1,
           "interfaces": [
             {"name":"wlan0","iface_type":"wifi","ssid":"office-5g","gateway_ip":"10.0.0.1"}
           ],
           "dns_suffix": ["corp.example.com"],
           "ttl": 1800
         }' \
     http://127.0.0.1:9090/network/context
```

离线（host 确认没有活跃 iface）推荐：

```bash
curl -X PUT -H 'Authorization: Bearer <secret>' -H 'Content-Type: application/json' \
     -d '{"version":1,"interfaces":[]}' http://127.0.0.1:9090/network/context
```

这会让内核按 `matched_network=<none>` 走 `default` / `no_change_no_default` 分支。**不要**发 DELETE 表达离线——DELETE 保留状态机、不走 default，见 §11.2。

### 11.2 `DELETE /network/context`

清除内核缓存的 ctx 快照（让"当前 ctx"视作 nil）。**不是**"状态机重置"：

- 各组 `selection_source` / `last_matched_network` / 已 selected proxy **全部保留**。
- **不触发评估、不写 cachefile、不走 `default`**。
- 若存在 ctx → 清快照 + 取消 TTL timer；若无 ctx → no-op。**两种情况都返回 `204`**。

用途限定三种场景：
1. host 进程 clean shutdown（放弃当前对话但不抹掉用户 manual 选择）；
2. host 显式想"kernel 侧无 ctx，保留状态机"；
3. TTL 自然失效（内核自动触发，等价 DELETE 语义，host 不参与）。

下次 PUT 到来时按保留的 `source` / `last_matched_network` 继续走 §11.1 状态机——特别是"manual 选择在同一 network 下继续尊重"语义继续生效。

**响应**：

| 状态 | body | 场景 |
|---|---|---|
| `204 No Content` | 空 | 成功（无论原先有无 ctx） |

**示例**：

```bash
curl -X DELETE -H 'Authorization: Bearer <secret>' \
     http://127.0.0.1:9090/network/context
```

### 11.3 `GET /network/context`

返回当前 ctx 快照 + 各组状态机快照，供 host 做周期性诊断刷新。

**响应** `200 OK`：

```jsonc
{
  "context": {                                // 归一化后的 PUT body；无 ctx 时为 null
    "version": 1,
    "interfaces": [
      {"name":"wlan0","iface_type":"wifi","ssid":"office-5g","gateway_ip":"10.0.0.1"}
    ],
    "dns_suffix": ["corp.example.com"]
    // ttl 不回显（用 expires_at + age_seconds 代替）
  },
  "matched_network": "office",                // wire null 编码见下方
  "groups": [                                 // 仅带 `network-policy` 的 select 组，按 YAML 声明顺序
    {
      "group": "auto",
      "current_proxy": "hk",
      "selection_source": "auto",             // auto | manual | unknown
      "last_matched_network": "office"        // wire null 编码见下方
    }
  ],
  "expires_at": 1713401800,                   // sticky 或无 ctx 时为 null
  "age_seconds": 42                           // 自上次 PUT 以来的秒数；无 ctx 时为 null
}
```

**无 ctx 时**（冷启动未 PUT / DELETE 后 / TTL 过期后）：`context` / `matched_network` / `expires_at` / `age_seconds` 全为 `null`，`groups[]` 仍按"每组一项"返回（含 `current_proxy` / `selection_source` / `last_matched_network`）。host 轮询逻辑不必做 200-vs-404 分支。

**`matched_network` / `last_matched_network` 的 wire null 编码**：

| 内部状态 | 含义 | wire JSON |
|---|---|---|
| 具体 name（如 `"office"`） | 评估命中 | JSON string `"office"` |
| `<none>`（内部哨兵） | 评估时 Match 未命中任一 network | JSON `null` |
| `nil`（仅 `last_matched_network` 可能是） | 从未评估过 | JSON `null` |

wire 层不暴露 `"<none>"` 字面量。host 可以配合 `selection_source` 推断内部状态：

- `source=unknown` + `last_matched_network=null` → 从未评估（内部 `nil`）。
- `source=auto` + `last_matched_network=null` → 已评估但未命中（内部 `<none>`）。
- `source=manual` + `last_matched_network=null` → **二义**：既可能是"首次 PUT 前先手动切"（内部 `nil`），也可能是"已评估无命中后再手动切"（内部 `<none>`）。host 一般不需要完全反推这两种情形；如需区分应结合自身交互上下文。

**示例**：

```bash
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/network/context
```

### 11.4 与 `PUT /proxies/{name}` 的协作

`PUT /proxies/{name}` 用于切换 select 组的选择。若被切换的组带 `network-policy` 字段，`proxies.go` 在 `selector.Set` 成功返回后调用 `networkpolicy.Global().HandleManualSet(name)`：

- 该组 `selection_source` 被标为 `manual`；`last_matched_network` 不变。
- 下次 `PUT /network/context` 时状态机按 §11.1 "手动 / 自动状态机"处理（同一 network 下 `manual_locked`；network 变化时 auto 接管）。
- 锁序：`globalMu → selector.mu → manager.mu`——hook 在 `selector.Set()` 返回**之后**调用（不持有 `selector.mu`），避免与 `manager.PutContext` 的锁序倒置。
- 不带 `network-policy` 的 select 组不进 hook；传统 `PUT /proxies/{name}` 行为完全不变。
- `PUT /proxies/{name}` 的外部契约（path / body / status / `SwitchProxiesCallback`）与既有 mihomo 行为等价。

### 11.5 错误响应 code 表

`/network/context` 三个 endpoint 共享下表（遵循 §11.0 的 `{"code","message"}` 包络）；`code` 是稳定标识，`message` 仅人类可读：

| code | HTTP | 场景 |
|---|---|---|
| `malformed_body` | 400 | JSON 解析失败 / 顶层非 object / 缺必填（`version` / `interfaces`）/ `dns_suffix` 非数组等字段形态错误（按 Go `encoding/json` 行为，字符串内非法 UTF-8 字节会被替换为 `U+FFFD` 而非拒绝） |
| `invalid_version` | 400 | `version != 1` |
| `invalid_ttl` | 400 | `ttl <= 0` 或 `> 10 年` |
| `too_many_interfaces` | 400 | `interfaces.len() > 32` |
| `duplicate_iface_name` | 400 | `interfaces[]` 中 `name` 重复 |
| `invalid_field` | 400 | 字段级校验失败（MAC / IP / CIDR / enum 格式错误；`name` 为空或 > 255 字节；`ssid` > 32 字节；`dns_suffix[]` 含逗号 / 空白 / 控制字符等）。`message` 采用 `field: <path>, reason: <why>` 约定 |
| `invalid_gateway_combo` | 400 | `gateway_mac` 填充但 `gateway_ip` 为空 |
| `internal_error` | 5xx | 未归类错误，包含 Manager 未初始化（配置未挂接 / 启动未完成） |

**host 处理建议**：
- `4xx` + 已知 code → log error 字段级内容，**不自动 retry**（配置 bug，retry 会放大日志）。
- `4xx` + `internal_error` / 未知 code → log 原样 payload。
- `5xx` → 按现有 retry 策略退避重试。

### 11.6 Listener 契约对应

`GET /configs` 的 `tun.device` 字段返回 listener 实际 bound 的 iface 名（`tunLister.Config().Device`），所有 Device 解析路径（auto-detect / invalid name / fd-override）在进入 `sing_tun.New` 成功后都把解析结果写回 `options.Device`。这让 host sampler 能用 `/configs.tun.device` 过滤"mihomo 自己的 TUN"，避免把它当成用户装的 VPN 上报给 `PUT /network/context`。

**caveats**：
- macOS utun 上的名字仍是 `CalculateInterfaceName()` 的 pre-bind 估计（"扫描空闲 utunN"），不是严格的 post-bind ground truth——极端竞争下可能与实际 bind 名不一致。
- fd-override 路径在 `getTunnelName(fd)` 失败时 `options.Device` 退回调用方原值（可能为空串）。

---

## 12. UI / DoH

### 12.1 `GET /ui` / `GET /ui/*`

仅当 `external-ui` 配置非空时挂载。

| 项目 | 值 |
|---|---|
| 鉴权 | 否（不在 `r.Group` 之内） |
| 来源 | `hub/route/server.go:144` |

**行为**：

- `GET /ui` → `307 Temporary Redirect` → `/ui/`
- `GET /ui/*` → 从 `external-ui` 指定的目录里 `http.FileServer` 服务静态资源（前缀剥离 `/ui`）。

资源更新见 `POST /upgrade/ui`（§10.3）。

### 12.2 DoH `external-doh-server`

仅当配置 `external-doh-server` 以 `/` 开头时把 `dohRouter()` 挂到该路径下，作为 RFC 8484 的 DoH 端点。

| 项目 | 值 |
|---|---|
| 鉴权 | 否（在 `r.Group` 之外） |
| 来源 | `hub/route/server.go:152`、`hub/route/doh.go:14` |

**支持方法**：`GET` 与 `POST`。

- **GET**：`?dns=<base64url(dns wire format)>`。请求示例：
  ```bash
  curl -H 'Accept: application/dns-message' \
       "https://controller.example.com/dns-query?dns=..."
  ```
- **POST**：必须 `Content-Type: application/dns-message`，body 是 ≤ 65535 B 的 DNS wire format。
  ```bash
  curl -X POST \
       -H 'Content-Type: application/dns-message' \
       --data-binary @query.bin \
       https://controller.example.com/dns-query
  ```

**响应**：

| 状态 | Content-Type | body |
|---|---|---|
| `200 OK` | `application/dns-message` | DNS wire format（resolver 返回值） |
| `405` | `text/plain` | `method not allowed` |
| `500` | `text/plain` | `DNS section is disabled` / `invalid content-type` / `<error>` |

> 与 `/dns/query` 不同：`/dns/query` 是 mihomo 自定义的 JSON GET，`dohRouter` 是标准 DoH。

---

## 13. Debug

> 仅当 `Config.IsDebug=true`（命令行 `-d`）时挂载，且 **不在已认证 group 之内** —— 不要把 debug + 非 loopback 暴露在外网。

挂载点：`/debug/*`。

| 子路径 | 方法 | 来源 | 说明 |
|---|---|---|---|
| `PUT /debug/gc` | PUT | `hub/route/server.go:109` | 触发 `runtime/debug.FreeOSMemory()`；无响应体（200 + 空 body） |
| `/debug/pprof/*` | GET | `chi/middleware.Profiler` | 标准 `net/http/pprof` 路径：`/debug/pprof/`、`/debug/pprof/heap`、`/debug/pprof/profile?seconds=30`、`/debug/pprof/goroutine?debug=2` 等 |

**示例**：

```bash
# 触发 GC
curl -X PUT http://127.0.0.1:9090/debug/gc

# 抓取 30 秒 CPU profile
curl -o cpu.pprof "http://127.0.0.1:9090/debug/pprof/profile?seconds=30"

# 查看 goroutine 堆栈
curl "http://127.0.0.1:9090/debug/pprof/goroutine?debug=2"
```

---

## 14. 错误体与状态码索引

### 14.1 错误体

```jsonc
// HTTPError（绝大多数 4xx/5xx）
{ "message": "Body invalid" }

// Network-policy envelope（仅 /network/context 三个 endpoint；详见 §11.5）
{ "code": "invalid_field", "message": "field: interfaces[0].gateway_ip, reason: parse error" }

// 上游兼容形态（仅以下 endpoint）
{ "status": "ok" }              // POST /restart, POST /upgrade, POST /upgrade/ui

// DoH（text/plain，非 JSON）
"DNS section is disabled"
```

预定义 sentinel（`hub/route/errors.go`）：

| 变量 | message |
|---|---|
| `ErrUnauthorized` | `Unauthorized` |
| `ErrBadRequest` | `Body invalid` |
| `ErrForbidden` | `Forbidden` |
| `ErrNotFound` | `Resource not found` |
| `ErrRequestTimeout` | `Timeout` |

### 14.2 状态码用例汇总

| 状态码 | 出现位置 |
|---|---|
| `200` | 所有 GET 成功；`PUT /proxies/.../delay`；`POST /restart` / `POST /upgrade` 的成功回执；`PUT /network/context` 成功 |
| `204` | `PUT /proxies/{name}`、`DELETE /proxies/{name}`、`PATCH /configs`、`PUT /configs`、`POST /configs/geo`、`PATCH /rules/disable`、`DELETE /connections*`、`POST /cache/*`、`PUT /providers/{name}`、`GET /providers/{name}/healthcheck`、`DELETE /network/context` |
| `307` | `GET /ui` → `/ui/` |
| `400` | body 解析失败、参数非法、`Selector` 操作不合法、`ManualSet` 触发的 `ErrNotSelectable` / `ErrProxyNotExist`、`NormalizeAndValidate` 报错 |
| `401` | 鉴权失败（`Authorization` 头或 `?token=` 不匹配） |
| `404` | `findProxyByName` / `findProviderByName` / `findRuleProviderByName` / `findProviderProxyByName` 找不到资源 |
| `405` | `wsUpgrade` 非 GET 方法、DoH 非 GET/POST |
| `426` | WebSocket 升级时 `Sec-WebSocket-Version` 不为 `13` |
| `500` | DNS 未启用、updater 失败、写盘失败、获取自身路径失败、防御性兜底 |
| `503` | `provider.Update()` 失败、`/proxies/.../delay` 失败但未超时、`networkpolicy` Manager 未就绪 |
| `504` | `/proxies/.../delay`、`/group/.../delay` 超时 |

---

## 15. 路由总表

| Method | Path | 鉴权 | 来源 | embedMode 屏蔽 |
|---|---|---|---|---|
| GET | `/` | 是 | `server.go:121` | 否 |
| GET | `/version` | 是 | `server.go:125` | 否 |
| GET | `/traffic` | 是（HTTP/WS） | `server.go:123` | 否 |
| GET | `/memory` | 是（HTTP/WS） | `server.go:124` | 否 |
| GET | `/logs` | 是（HTTP/WS） | `server.go:122` | 否 |
| GET | `/configs` | 是 | `configs.go:27` | 否 |
| PUT | `/configs` | 是 | `configs.go:29` | 是 |
| PATCH | `/configs` | 是 | `configs.go:31` | 是 |
| POST | `/configs/geo` | 是 | `configs.go:30` | 是 |
| GET | `/proxies` | 是 | `proxies.go:28` | 否 |
| GET | `/proxies/{name}` | 是 | `proxies.go:32` | 否 |
| GET | `/proxies/{name}/delay` | 是 | `proxies.go:33` | 否 |
| PUT | `/proxies/{name}` | 是 | `proxies.go:34` | 否 |
| DELETE | `/proxies/{name}` | 是 | `proxies.go:35` | 否 |
| GET | `/group` | 是 | `groups.go:21` | 否 |
| GET | `/group/{name}` | 是 | `groups.go:25` | 否 |
| GET | `/group/{name}/delay` | 是 | `groups.go:26` | 否 |
| GET | `/rules` | 是 | `rules.go:16` | 否 |
| PATCH | `/rules/disable` | 是 | `rules.go:18` | 是 |
| GET | `/connections` | 是（HTTP/WS） | `connections.go:18` | 否 |
| DELETE | `/connections` | 是 | `connections.go:19` | 否 |
| DELETE | `/connections/{id}` | 是 | `connections.go:20` | 否 |
| GET | `/providers/proxies` | 是 | `provider.go:18` | 否 |
| GET | `/providers/proxies/{providerName}` | 是 | `provider.go:22` | 否 |
| PUT | `/providers/proxies/{providerName}` | 是 | `provider.go:23` | 否 |
| GET | `/providers/proxies/{providerName}/healthcheck` | 是 | `provider.go:24` | 否 |
| GET | `/providers/proxies/{providerName}/{name}` | 是 | `provider.go:34` | 否 |
| GET | `/providers/proxies/{providerName}/{name}/healthcheck` | 是 | `provider.go:35` | 否 |
| GET | `/providers/rules` | 是 | `provider.go:115` | 否 |
| PUT | `/providers/rules/{name}` | 是 | `provider.go:118` | 否 |
| POST | `/cache/fakeip/flush` | 是 | `cache.go:13` | 否 |
| POST | `/cache/dns/flush` | 是 | `cache.go:14` | 否 |
| GET | `/dns/query` | 是 | `dns.go:18` | 否 |
| POST | `/restart` | 是 | `restart.go:20` | 是（整段不挂载） |
| POST | `/upgrade` | 是 | `upgrade.go:19` | 是 |
| POST | `/upgrade/geo` | 是 | `upgrade.go:20` | 是 |
| POST | `/upgrade/ui` | 是 | `upgrade.go:17` | 否 |
| GET | `/storage/{key}` | 是 | `storage.go:16` | 否 |
| PUT | `/storage/{key}` | 是 | `storage.go:17` | 否 |
| DELETE | `/storage/{key}` | 是 | `storage.go:18` | 否 |
| PUT | `/network/context` | 是 | `network.go:putNetworkContext` | 否 |
| DELETE | `/network/context` | 是 | `network.go:deleteNetworkContext` | 否 |
| GET | `/network/context` | 是 | `network.go:getNetworkContext` | 否 |
| GET | `/ui`、`/ui/*` | 否 | `server.go:144`（条件挂载） | 否 |
| GET/POST | `<external-doh-server path>` | 否 | `server.go:152`（条件挂载） | 否 |
| PUT | `/debug/gc` | 否 | `server.go:109`（仅 IsDebug） | 否 |
| ANY | `/debug/pprof/*` | 否 | `chi/middleware.Profiler`（仅 IsDebug） | 否 |

---

## 16. 与 Clash Premium / Clash Meta API 的差异提示

mihomo 在 Clash Premium 基础上扩展了若干字段与 endpoint，本节仅列出与"原版 Clash"显著差异的点：

- `/proxies/{name}` 输出的字段集更广（`alive` / `extra` / `xudp` / `tfo` / `mptcp` / `smux` / `provider-name` / `dialer-proxy` 等）。
- `/group/{name}/delay` 的副作用：对 Selector 之外的组会重置 fixed 状态。
- `/rules` 输出新增 `extra`（hit/miss 计数），`size`（GEOIP/GEOSITE 包含数）。
- `PATCH /rules/disable`、`POST /upgrade`、`POST /upgrade/ui`、`/dns/query`、`/cache/fakeip/flush` 等 endpoint 是 mihomo 新增。
- `/version` 返回 `meta: true`。
- `/network/context`（见 §11）是 mihomo 的 network-policy 控制面。

---

> 文档末尾。如需对接 mihomo API，建议优先以本文档与 `hub/route/` 源码为准；上游 OpenAPI 工作（如 [clash-meta-api-doc](https://github.com/MetaCubeX/Clash.Meta.Doc)）可作辅助参考但与本仓库行为可能略有差异。
