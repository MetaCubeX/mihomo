# multiple-proxy 设计文档

日期：2026-10-11
状态：待评审

## 1. 目标

在 mihomo 中支持配置多个独立代理监听端口。每个端口拥有自己的路由行为——独立的
`mode`、独立的规则集、可选的固定出口组（`proxy-group`）或按节点名筛选动态生成的
出口组（`matchs`）。不同客户端/应用连接不同端口即可获得不同的分流结果。

`proxies`、`proxy-groups`、`proxy-providers`、`rule-providers`、DNS 等全局资源
仍然共享；只有「mode + 规则集 + 兜底出口」是按端口隔离的。

### 成功标准

- 配置 `multiple-proxy` 后，每个端口按自己的 mode/rules 工作。
- 能够通过日志、API（`/proxies`）和 dashboard 看出某个连接走的是哪套规则/哪个组。
- 现有 `mixed-port` / `port` / `socks-port` / `listeners:` 行为完全不变（向后兼容）。

## 2. 配置结构

```yaml
multiple-proxy:
  - name: hk                  # 可选；默认 multiple-proxy-<序号>；用于日志/API/监听器名
    mixed-port: 7890          # 三选一：mixed-port / port / socks-port
    mode: global              # global | rule | direct；省略则继承全局 mode
    enable-global-rule: true  # 仅本条目：以全局 rules 为基底
    rules:                    # 仅本条目：插入到基底 MATCH 之前
      - DOMAIN-SUFFIX,acl4.ssr,🎯 全球直连
    proxy-group: "🚀 节点选择"  # 可选：引用已有 proxy-groups 中的组
    matchs:                   # 可选：从 proxies 筛节点现场生成一个组
      - name: "*香港*|*台湾*"
        type: select          # select | url-test | fallback | load-balance，默认 select
        default-selected: HK-01  # 可选，仅 select；生成的组的初始选中节点
```

### 字段语义

| 字段 | 必填 | 说明 |
|---|---|---|
| `name` | 否 | 条目名。缺省为 `multiple-proxy-<序号>`。用作监听器名与生成的组名/规则集名的前缀 |
| `mixed-port` / `port` / `socks-port` | 是（三选一） | 监听端口。**恰好**指定一个；缺失或多个都报错 |
| `mode` | 否 | `global` / `rule` / `direct`。省略则继承全局 mode |
| `enable-global-rule` | 否 | 仅本条目。为 true 时以全局 `rules` 为基底（见「规则集语义」） |
| `rules` | 否 | 仅本条目。插入到基底 catch-all `MATCH` 之前。格式与顶层 `rules` 相同 |
| `proxy-group` | 否 | 引用 `proxy-groups` 中已存在的组名作为出口 |
| `matchs` | 否 | 从 `proxies` 中按名字模式筛选节点，现场合成一个出口组 |
| `matchs[].name` | 是 | 通配模式（`*` 匹配任意字符，`?` 匹配单字符；**不支持正则**），用于匹配节点名 |
| `matchs[].type` | 否 | 生成组的类型，默认 `select` |
| `matchs[].default-selected` | 否 | 仅 `select`：生成组的初始选中节点名 |

### 出口优先级

`proxy-group` > `matchs` 生成的组 > 模式回落（`global` → `GLOBAL`；`rule` → 规则兜底
`DIRECT`）。

- `proxy-group` 与 `matchs` 同时存在时，**以 `proxy-group` 为准**（`matchs` 仍会被
  解析并校验，但不参与出口选择）。
- `direct` 模式下，出口恒为 `DIRECT`，`proxy-group` / `matchs` 被忽略。

### 规则集语义

**何时建端口专属规则集**：当且仅当条目配置了路由意图，即
`enable-global-rule: true` **或** `rules` 非空。两者都不满足时，该端口不建规则集，
直接沿用全局 `rules`（行为与不配置 `multiple-proxy` 时一致）。

这保证了「什么都没配的条目 = 全局行为」，避免出现空规则集导致全部流量走兜底的
静默行为改变。

**合成方式**：

- `enable-global-rule: true` → 以顶层全局 `rules` 为**只读基底**（不修改全局）。
- 本条目 `rules` 插入到基底的 **catch-all `MATCH` 规则之前**（若基底存在
  `MATCH` 规则）；基底没有 `MATCH` 时追加到末尾。
  - 原因：`MATCH` 匹配一切，追加在它之后的本条目规则永远不会命中，会成为死代码。
    插到它之前才能生效，同时保留「全局规则优先、本条目规则补位」的语义。
- `enable-global-rule: false`（或省略）→ 基底为空，本条目 `rules` 即为全部规则
  （无 `MATCH` 时不做插入处理，直接使用）。
- 合成结果**只挂在当前端口的连接上**（写入 `subRules[multiple-proxy-<name>]`），
  全局 `rules` 与其它端口完全不受影响。
- 合成后的规则集**仅在端口有效 mode 为 `rule` 时被使用**；`global` / `direct` 模式
  下规则集不参与路由（见「mode 语义」）。
- `rules` 中引用的 target（组名/节点名）必须已存在于 `proxies`，否则解析报错
  （复用现有 `parseRules` 的校验）。

### mode 语义（关键）

- `mode: global` → 该端口**不走规则**，全部流量走该端口的出口组。
- `mode: rule` → 走该端口的规则集。**命中规则就走规则里写的那个组**；规则全不命中
  （落到兜底）时，若该端口配置了 `proxy-group` / `matchs` 出口，则改用它，否则用
  `DIRECT`。
- `mode: direct` → 全部直连。
- 省略 `mode` → 继承全局 mode。此时规则集沿用全局 `rules`，无端口级规则覆盖；
  但若该条目配置了 `proxy-group` / `matchs` 出口，则 `fallback-proxy` 仍会写入该
  监听器，规则全不命中时改用该出口（见「出口优先级」），此点与「全局 mode 的
  `GLOBAL` 兜底」不同。

### 边界与校验

- `multiple-proxy` 的端口不得与任何其它已监听端口（`port` / `socks-port` /
  `mixed-port` / `listeners:` / 其它 `multiple-proxy` 条目）冲突，冲突则报错。
- `matchs` 匹配到 0 个节点 → **报错**（fail-fast，避免静默走错出口）。
- 多个 `matchs` 条目的 `name` 模式取**并集**，合成同一个组；`type` 若不一致则报错。
- `matchs[].default-selected` 指定的节点必须存在于筛选结果中，否则报错。
- `proxy-group` 指定的组必须存在，否则报错。

### select 组的固定节点

`select` 组的选中逻辑：

1. **启动时固定**：通过 `matchs[].default-selected` 指定初始节点；不写则沿用 mihomo
   默认（组内第一个节点）。
2. **运行期切换**：生成的组注册进 `proxies`，因此会出现在 dashboard / API 代理列表
   中，可随时手动切换。配合顶层 `profile.store-selected: true` 可持久化，重启后保持。
3. **真正不可切换的固定出口**：不使用 `select`——`proxy-group` 可直接写单个节点名，
   或用 `url-test` 自动选择。

## 3. 架构

### 3.1 复用的现有接缝

mihomo 现有代码已提供两个 per-connection 覆盖机制，本设计在其上扩展：

- `metadata.SpecialRules` → `tunnel.getRules()` 按名切换规则集（`tunnel/tunnel.go:713`）。
- `metadata.SpecialProxy` → `tunnel.resolveMetadata()` 硬覆盖出口，绕过规则与 mode
  （`tunnel/tunnel.go:317`）。
- `listener/inbound/base.go` 的 `BaseOption` 已支持 `rule:` / `proxy:` 两个
  inbound tag，`Additions()` 负责注入 metadata。
- `listener.ParseListener()` 按 `type` 构造监听器，`PatchInboundListeners()` 以
  `Config().Equal` 做 reload diff。

### 3.2 新增的接缝

在 `C.Metadata` 与 `BaseOption` 上新增两个字段：

- `SpecialMode`（覆盖全局 mode）——新增，因当前 mode 是纯全局单例。
- `SpecialFallbackProxy`（规则兜底出口）——新增，用于 rule 模式下的兜底换组。

`C.Metadata` 新增字段（`constant/metadata.go`）：

```go
SpecialMode          string `json:"specialMode"`
SpecialFallbackProxy string `json:"specialFallbackProxy"`
```

`BaseOption` 新增 inbound tag（`listener/inbound/base.go`）：

```go
SpecialMode          string `inbound:"mode,omitempty"`
SpecialFallbackProxy string `inbound:"fallback-proxy,omitempty"`
```

并在 `Additions()` 中追加对应的 `WithSpecialMode` / `WithSpecialFallbackProxy`
（`adapter/inbound/addition.go`）。

### 3.3 解析期流水线

新增 `parseMultipleProxy(cfg, proxies, providers, subRules)`，插入位置在
`parseProxies` 之后、`parseListeners` 之前（`config/config.go:677-704` 之间）。

**顺序约束**：`parseRules` 会校验规则的 target 必须已存在于 `proxies`
（`config/config.go:1107`）。因此 matchs 生成的组必须在 `parseProxies` 阶段就注册
进 `proxies`，端口专属规则集才能通过校验。

对每个 `multiple-proxy` 条目：

1. **建出口组**
   - 有 `proxy-group` → 直接引用该名字。
   - 否则有 `matchs` → 用 `outboundgroup.NewSelector`（或对应类型构造器）新建组：
     - 组名：`multiple-proxy-<name>`（保证唯一，不与用户组重名；重名则报错）。
     - 成员：`proxies` 中名字命中任一 `matchs[].name` 通配的节点，多个模式取并集。
     - `type` 决定构造器；`select` 时用 `SelectorOption{DefaultSelected: ...}`。
     - 注册进 `proxies` 与 `providers`，使其在 API/dashboard 可见、可切换。
   - 匹配到 0 个节点 → 报错。
2. **建专属规则集**（仅当 `enable-global-rule` 为 true 或 `rules` 非空）
   - `enable-global-rule` 为 true 时以全局 `rules` 为基底，把本条目 `rules` 插入到
     基底的 catch-all `MATCH` 之前（无 `MATCH` 则追加末尾）；否则仅用本条目 `rules`。
   - 以生成名（`multiple-proxy-<name>`）写入 `subRules`。该规则集**仅本条目使用**。
   - 未配置路由意图时不建规则集，该端口沿用全局 `rules`。
3. **建监听器**
   - 构造 listener mapping：
     ```go
     map[string]any{
       "type":           "mixed" | "http" | "socks",  // 由端口字段决定
       "name":           name,
       "port":           port,
       "rule":           generatedRuleSetName,   // 仅当建了规则集（见上一步）
       "mode":           effectiveMode,          // 仅当条目显式指定 mode
       "fallback-proxy": exitGroupName,          // 出口组（有 proxy-group/matchs 时）
     }
     ```
   - 交给现有 `listener.ParseListener(mapping)` → 进 `config.Listeners`。
   - 复用全部现有生命周期（启动、reload diff、关闭）。

**规则合并的实现层级**：规则集在**原始字符串层**合并（`rawCfg.Rule` 与条目
`rules`，均为 `[]string`），再交给 `parseRules` 编译。这样能精确定位 `MATCH` 并
在它之前插入，也复用了 `parseSubRules` 已有的「raw strings → `[]C.Rule`」路径。

### 3.4 运行期路由

修改 `tunnel/resolveMetadata`（`tunnel/tunnel.go:317`）：

```go
func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
    if metadata.SpecialProxy != "" {
        // 现有硬覆盖，行为不变
        ...
    }

    // ... 现有 helper 构造 ...

    switch effectiveMode(metadata) {
    case Direct:
        proxy = proxies["DIRECT"]
    case Global:
        proxy = fallbackProxy(metadata)   // SpecialFallbackProxy 有则用之，否则 GLOBAL
    default: // Rule
        proxy, rule, err = match(metadata, helper)
        proxy, rule, err = applyFallback(proxy, rule, err, metadata)
    }
    return
}

func effectiveMode(metadata *C.Metadata) TunnelMode {
    if metadata.SpecialMode != "" {
        if m, ok := ModeMapping[metadata.SpecialMode]; ok {
            return m
        }
    }
    return mode   // 全局
}

func applyFallback(proxy C.Proxy, rule C.Rule, err error, metadata *C.Metadata) (C.Proxy, C.Rule, error) {
    // 仅当该端口显式配置了出口（proxy-group/matchs）时才换组。
    if err == nil && rule == nil && metadata.SpecialFallbackProxy != "" {
        if fb := fallbackProxy(metadata); fb != nil {
            proxy = fb
        }
    }
    return proxy, rule, err
}
```

`fallbackProxy` 查 `proxies[metadata.SpecialFallbackProxy]`，查不到则回落到
`proxies["GLOBAL"]`。

**关键信号**：`match()` 在规则全不命中时返回 `proxies["DIRECT"]` 且 `rule == nil`
（`tunnel/tunnel.go:708`）。这个 `nil` rule 是「兜底」的可靠判据。

**注意 `metadata.SpecialFallbackProxy != ""` 这个前置条件**：没有它，`fallbackProxy`
在空 `SpecialFallbackProxy` 时会回落到 `proxies["GLOBAL"]`，把 `match` 的
「全不命中 → `DIRECT`」结果错误地改写成 `GLOBAL`——这会破坏「未配置端口的 rule 模式
兜底为 `DIRECT`」的既有语义（见「出口优先级」）。只有显式配置了出口的端口才换组。

### 3.5 兼容性

- 旧 `mixed-port` / `port` / `socks-port` / `listeners:` 行为零改动：
  `SpecialMode` / `SpecialFallbackProxy` 默认空字符串 → 走全局 mode 与现有逻辑。
- 全局 mode 的 API 与 `/configs` PATCH 语义不变（`hub/route/configs.go:383`、
  `hub/executor/executor.go:394`）。端口级 mode 是只读的、由配置决定。
- reload 走 `PatchInboundListeners` 的 `Config().Equal` diff，自动生效；生成的组与
  规则集每次 Parse 重新生成，无残留。

## 4. 组件划分

| 组件 | 位置 | 职责 |
|---|---|---|
| 配置解析 | `config/config.go` 新增 `parseMultipleProxy` | 读 `multiple-proxy`，建组、建规则集、建 listener mapping |
| Raw 配置 | `config/config.go` `RawConfig` | 新增 `MultipleProxy []RawMultipleProxy` 字段 |
| Metadata 扩展 | `constant/metadata.go` | `SpecialMode` / `SpecialFallbackProxy` |
| Inbound 扩展 | `listener/inbound/base.go` + `adapter/inbound/addition.go` | 两个新 inbound tag 与 Addition |
| 路由决策 | `tunnel/tunnel.go` `resolveMetadata` | `effectiveMode` 分支 + 兜底换组 |

每个组件单一职责、通过既有接口通信，可独立测试。

## 5. 错误处理

全部为**配置解析期 fail-fast**，报错即配置不生效（与 mihomo 现有 `parseRules`
风格一致）：

- 端口字段缺失或指定多个。
- 端口与其它监听端口冲突。
- `proxy-group` 引用的组不存在。
- `matchs` 匹配到 0 个节点。
- 多个 `matchs` 条目的 `type` 不一致。
- `matchs[].default-selected` 不在筛选结果中。
- 生成的组名与已有组重名。
- 本条目 `rules` 的 target 不存在（复用现有校验）。

## 6. 测试

### 单元测试（`config`）

- 各字段解析正确，缺省值正确（`name` 自动生成、`type` 默认 `select`、`mode` 继承）。
- 出口优先级：`proxy-group` 存在时覆盖 `matchs`。
- 规则合并：
  - `enable-global-rule` 开 + `rules` 非空 → 合成规则集 = 全局规则（含 `MATCH`）
    且本条目 `rules` 位于 `MATCH` **之前**，能在 `MATCH` 兜底前命中。
  - 基底无 `MATCH` 时，本条目 `rules` 追加到末尾。
  - `enable-global-rule` 关 → 合成规则集仅含本条目 `rules`。
  - `enable-global-rule` 关且 `rules` 为空 → **不建规则集**，该端口沿用全局
    `rules`。
  - 以上所有情况，全局 `rules` 与其它 `subRules` 均未被修改。
- 规则集在 `global` / `direct` 模式下不参与路由。
- matchs 组生成：多模式并集、类型可配置、`default-selected` 生效。
- 上述全部错误场景各自报错。

### 单元测试（`tunnel`）

- `effectiveMode`：`SpecialMode` 有/无、非法值回落到全局。
- rule 模式：规则命中时用规则目标（不被兜底覆盖）；规则全不命中时用
  `SpecialFallbackProxy`。
- global 模式：用 `SpecialFallbackProxy`；未配置时用 `GLOBAL`。
- 无 `SpecialMode`/`SpecialFallbackProxy` 时行为与改动前完全一致（回归）。

### 回归

- 现有全部测试通过。

## 7. 明确不做（YAGNI）

- 不做端口级独立 DNS、独立 `proxies` / `proxy-providers` 视图。
- 不做端口级 mode 的运行期 API 修改（只读，由配置决定）。
- 不做每端口独立的 selector 状态隔离（同一组在多端口间共享选中状态，符合
  「组是全局资源」的模型）。
- 不引入按端口号查表的全局路由表（绕开 listener 抽象，reload 难同步）。
