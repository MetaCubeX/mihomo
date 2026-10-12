# multiple-proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `multiple-proxy` config block so a single mihomo instance can expose several independent inbound ports, each with its own routing mode, rule set, and fallback exit group.

**Architecture:** Reuse mihomo's existing per-connection override seams. Two new metadata fields (`SpecialMode`, `SpecialFallbackProxy`) plumbed through the existing inbound `Addition` mechanism; a new `parseMultipleProxy` phase in the config pipeline that synthesizes outbound groups (via the existing `outboundgroup.ParseProxyGroup`) and per-port rule sets (via the existing `parseRules`), then emits ordinary `listeners:` mappings so all existing listener lifecycle/reload code applies unchanged; and a small change to `tunnel.resolveMetadata` that consults the per-connection mode and fallback.

**Tech Stack:** Go 1.20+, `github.com/metacubex/mihomo` module. YAML via existing `RawConfig`. Tests: stdlib `testing` + `github.com/stretchr/testify/assert`.

**Spec:** `docs/superpowers/specs/2026-10-11-multiple-proxy-design.md`

## Global Constraints

- Module path: `github.com/metacubex/mihomo` (imports use this prefix).
- Do not change existing behavior for `port` / `socks-port` / `mixed-port` / `listeners:` — `SpecialMode` / `SpecialFallbackProxy` default to `""` and must fall through to the current code path.
- All validation is **parse-time fail-fast**: a bad `multiple-proxy` entry must make the whole config fail to load (return a non-nil `error`), never a silent fallback.
- `multiple-proxy` entries must not modify global `rules`, global `subRules` (other keys), or other ports.
- `matchs[].name` uses mihomo's wildcard matcher `component/wildcard.Match` (`*` = zero+ chars, `?` = one char). Alternatives are separated by `|` (e.g. `*香港*|*台湾*`); a node matches if it matches **any** alternative. (This is the literal form of the user's example; regex is intentionally not supported — YAGNI.)
- Generated names: internal id `id = name` when `name` is set, else `multiple-proxy-<idx>` (idx is the entry's 0-based index). Listener name = `id`. Generated group name = `id + "-group"`. Generated rule-set name = `id + "-rules"`.
- Reserved proxy names that must never be matched as matchs nodes: `DIRECT`, `REJECT`, `REJECT-DROP`, `COMPATIBLE`, `PASS`, `PASS-RULE`, `GLOBAL`.

## Review Focus

Input classes the spec implies but whose tests are not otherwise spelled out — each is pinned to a test in its owning task:

1. A `listeners:` entry whose `port` is a **range** (e.g. `"8000-8010"`) overlapping a `multiple-proxy` port — expect a parse error, not a late bind failure. (Task 2)
2. `enable-global-rule: true` where global `rules` ends in a catch-all `MATCH` — the entry's own rules must remain reachable (inserted **before** `MATCH`), verified by evaluating the compiled rule set. (Task 4)
3. A `matchs[].name` pattern that matches **0** nodes (e.g. a typo) — expect a parse error, not an empty group that silently routes to `DIRECT`. (Task 3)
4. `mode` **omitted** on an entry — must inherit the global mode at request time (not be frozen to a value at parse time). (Task 5)
5. Removing a `multiple-proxy` entry across a reload — its listener must be closed by the existing `PatchInboundListeners` diff and the generated group must not linger. (Task 4, integration)

---

### Task 1: Metadata + inbound plumbing for `SpecialMode` / `SpecialFallbackProxy`

**Files:**
- Modify: `constant/metadata.go:211` (add two fields after `SpecialRules`)
- Modify: `adapter/inbound/addition.go` (add two `Addition` constructors after `WithSpecialProxy`)
- Modify: `listener/inbound/base.go:92-104` (`BaseOption` fields) and `:114-120` (`Additions()`)
- Test: `listener/inbound/base_test.go` (create)

**Interfaces:**
- Consumes: existing `inbound.Addition`, `C.Metadata`, `BaseOption.Additions()`.
- Produces:
  - `C.Metadata.SpecialMode string`, `C.Metadata.SpecialFallbackProxy string`
  - `inbound.WithSpecialMode(mode string) inbound.Addition`, `inbound.WithSpecialFallbackProxy(proxy string) inbound.Addition`
  - `BaseOption.SpecialMode string` (`inbound:"mode,omitempty"`), `BaseOption.SpecialFallbackProxy string` (`inbound:"fallback-proxy,omitempty"`), emitted by `Additions()`.

- [ ] **Step 1: Write the failing test**

```go
// listener/inbound/base_test.go
package inbound

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseOptionSpecialFields(t *testing.T) {
	opt := &BaseOption{NameStr: "mp-0", SpecialMode: "global", SpecialFallbackProxy: "MP-0-group"}
	base, err := NewBase(opt)
	assert.NoError(t, err)

	md := C.Metadata{}
	for _, add := range base.Additions() {
		add(&md)
	}
	assert.Equal(t, "mp-0", md.InName)
	assert.Equal(t, "global", md.SpecialMode)
	assert.Equal(t, "MP-0-group", md.SpecialFallbackProxy)
}
```

(Add `C "github.com/metacubex/mihomo/constant"` to the test imports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./listener/inbound/ -run TestBaseOptionSpecialFields -v`
Expected: FAIL — compile error, `C.Metadata` has no field `SpecialMode`.

- [ ] **Step 3: Implement the fields**

In `constant/metadata.go`, after `SpecialRules string`:
```go
SpecialMode          string `json:"specialMode"`
SpecialFallbackProxy string `json:"specialFallbackProxy"`
```

In `adapter/inbound/addition.go`, after `WithSpecialProxy`:
```go
func WithSpecialMode(specialMode string) Addition {
	return func(metadata *C.Metadata) {
		metadata.SpecialMode = specialMode
	}
}

func WithSpecialFallbackProxy(specialFallbackProxy string) Addition {
	return func(metadata *C.Metadata) {
		metadata.SpecialFallbackProxy = specialFallbackProxy
	}
}
```

In `listener/inbound/base.go`, add to `BaseOption` after `SpecialProxy`:
```go
SpecialMode          string `inbound:"mode,omitempty"`
SpecialFallbackProxy string `inbound:"fallback-proxy,omitempty"`
```
and append to `Additions()`:
```go
inbound.WithSpecialMode(o.SpecialMode),
inbound.WithSpecialFallbackProxy(o.SpecialFallbackProxy),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./listener/inbound/ -run TestBaseOptionSpecialFields -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add constant/metadata.go adapter/inbound/addition.go listener/inbound/base.go listener/inbound/base_test.go
git commit -m "feat(inbound): add per-listener SpecialMode and SpecialFallbackProxy metadata"
```

---

### Task 2: `RawMultipleProxy` config types + validation helpers

**Files:**
- Modify: `config/config.go` (add `RawMultipleProxy`/`RawMatchsEntry` types near `RawConfig`; add `MultipleProxy []RawMultipleProxy` to `RawConfig`)
- Create: `config/multiple_proxy.go` (helpers)
- Test: `config/multiple_proxy_test.go` (create)

**Interfaces:**
- Consumes: `C.TunnelMode`, `T.ModeMapping`, `utils.NewUnsignedRanges[uint16]`, `C.InboundListener`.
- Produces (all in package `config`, file `config/multiple_proxy.go`):
  - `type RawMatchsEntry struct { Name, Type, DefaultSelected string }`
  - `type RawMultipleProxy struct { Name string; MixedPort, Port, SocksPort int; Mode string; EnableGlobalRule bool; Rules []string; ProxyGroup string; Matchs []RawMatchsEntry }`
  - `func multipleProxyListenerType(entry RawMultipleProxy) (ltype string, port int, err error)` — returns `"mixed"|"http"|"socks"` + the single port; errors if not exactly one of the three is set.
  - `func validateMultipleProxyMode(mode string) error` — `""` ok; otherwise must be a key of `T.ModeMapping`.
  - `func collectUsedPorts(cfg *RawConfig) (map[uint16]string, error)` — port → owner description, from `Port`/`SocksPort`/`MixedPort`/`RedirPort`/`TProxyPort` and every `cfg.Listeners[i]["port"]` (parsed as an unsigned range, expanded).
  - `func multipleProxyID(entry RawMultipleProxy, idx int) string`

- [ ] **Step 1: Write the failing test**

```go
// config/multiple_proxy_test.go
package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultipleProxyListenerType(t *testing.T) {
	cases := []struct {
		name    string
		entry   RawMultipleProxy
		wantT   string
		wantP   int
		wantErr bool
	}{
		{"mixed", RawMultipleProxy{MixedPort: 7890}, "mixed", 7890, false},
		{"http", RawMultipleProxy{Port: 7891}, "http", 7891, false},
		{"socks", RawMultipleProxy{SocksPort: 7892}, "socks", 7892, false},
		{"none", RawMultipleProxy{}, "", 0, true},
		{"two", RawMultipleProxy{MixedPort: 7890, Port: 7891}, "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ltype, port, err := multipleProxyListenerType(c.entry)
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.wantT, ltype)
			assert.Equal(t, c.wantP, port)
		})
	}
}

func TestValidateMultipleProxyMode(t *testing.T) {
	assert.NoError(t, validateMultipleProxyMode(""))
	assert.NoError(t, validateMultipleProxyMode("global"))
	assert.NoError(t, validateMultipleProxyMode("rule"))
	assert.NoError(t, validateMultipleProxyMode("direct"))
	assert.Error(t, validateMultipleProxyMode("bogus"))
}

func TestCollectUsedPortsRange(t *testing.T) {
	cfg := &RawConfig{
		MixedPort: 7890,
		Listeners: []map[string]any{{"name": "x", "port": "8000-8002"}},
	}
	used, err := collectUsedPorts(cfg)
	assert.NoError(t, err)
	assert.Equal(t, "mixed-port", used[7890])
	assert.Contains(t, used[8000], "listener")
	assert.Contains(t, used[8001], "listener")
	assert.Contains(t, used[8002], "listener")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run 'TestMultipleProxyListenerType|TestValidateMultipleProxyMode|TestCollectUsedPortsRange' -v`
Expected: FAIL — undefined `multipleProxyListenerType` etc.

- [ ] **Step 3: Implement**

Add to `config/config.go` (near `RawConfig`):
```go
type RawMatchsEntry struct {
	Name            string `yaml:"name" json:"name"`
	Type            string `yaml:"type" json:"type"`
	DefaultSelected string `yaml:"default-selected" json:"default-selected"`
}

type RawMultipleProxy struct {
	Name             string           `yaml:"name" json:"name"`
	MixedPort        int              `yaml:"mixed-port" json:"mixed-port"`
	Port             int              `yaml:"port" json:"port"`
	SocksPort        int              `yaml:"socks-port" json:"socks-port"`
	Mode             string           `yaml:"mode" json:"mode"`
	EnableGlobalRule bool             `yaml:"enable-global-rule" json:"enable-global-rule"`
	Rules            []string         `yaml:"rules" json:"rules"`
	ProxyGroup       string           `yaml:"proxy-group" json:"proxy-group"`
	Matchs           []RawMatchsEntry `yaml:"matchs" json:"matchs"`
}
```
and to `RawConfig` (next to `Listeners`):
```go
MultipleProxy []RawMultipleProxy `yaml:"multiple-proxy" json:"multiple-proxy"`
```

Create `config/multiple_proxy.go` with the four helpers. `multipleProxyListenerType` counts how many of the three ports are non-zero and errors unless exactly one. `collectUsedPorts` seeds from the scalar port fields (skipping zeros) then, for each listener mapping, reads `mapping["port"].(string)` and enumerates via `utils.NewUnsignedRanges[uint16]`; a parse error is returned. `multipleProxyID` returns `entry.Name` when non-empty, else `fmt.Sprintf("multiple-proxy-%d", idx)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./config/ -run 'TestMultipleProxyListenerType|TestValidateMultipleProxyMode|TestCollectUsedPortsRange' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add config/config.go config/multiple_proxy.go config/multiple_proxy_test.go
git commit -m "feat(config): add multiple-proxy raw types and validation helpers"
```

---

### Task 3: matchs group synthesis

**Files:**
- Modify: `config/multiple_proxy.go`
- Test: `config/multiple_proxy_test.go`

**Interfaces:**
- Consumes: `outboundgroup.ParseProxyGroup`, `component/wildcard.Match`, `adapter.NewProxy`, `provider.NewCompatibleProvider` (indirectly), the `proxies`/`providersMap` maps.
- Produces:
  - `func isMatchableProxy(name string, p C.Proxy) bool` — false for the reserved names and for anything whose `p.Adapter()` implements `outboundgroup.ProxyGroup`.
  - `func buildMatchsGroup(groupName string, entries []RawMatchsEntry, proxies map[string]C.Proxy, providersMap map[string]P.ProxyProvider) (C.Proxy, error)` — filters `proxies`, unions all patterns (splitting each `entries[i].Name` on `|`), validates type uniformity + `default-selected`, builds the group by calling `outboundgroup.ParseProxyGroup` with a synthetic mapping `{"name","type","proxies",["default-selected"]}`, and registers it into `proxies` + `providersMap`.

- [ ] **Step 1: Write the failing test**

```go
func testProxiesMap(names ...string) map[string]C.Proxy {
	m := map[string]C.Proxy{
		"DIRECT":     adapter.NewProxy(outbound.NewDirect()),
		"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
		"GLOBAL":     adapter.NewProxy(outbound.NewDirect()), // stand-in group slot
	}
	for _, n := range names {
		m[n] = adapter.NewProxy(outbound.NewDirect())
	}
	return m
}

func TestBuildMatchsGroupUnionAndDefault(t *testing.T) {
	proxies := testProxiesMap("HK-01", "HK-02", "TW-01", "US-01")
	providers := map[string]P.ProxyProvider{}
	g, err := buildMatchsGroup("mp-0-group", []RawMatchsEntry{
		{Name: "*HK*"},
		{Name: "*TW*", DefaultSelected: "TW-01"},
	}, proxies, providers)
	assert.NoError(t, err)
	assert.Equal(t, "mp-0-group", g.Name())
	names := []string{}
	for _, p := range g.Adapter().(*outboundgroup.Selector).Proxies() {
		names = append(names, p.Name())
	}
	assert.ElementsMatch(t, []string{"HK-01", "HK-02", "TW-01"}, names)
	assert.Contains(t, proxies, "mp-0-group")
	assert.Contains(t, providers, "mp-0-group")
}

func TestBuildMatchsGroupErrors(t *testing.T) {
	proxies := testProxiesMap("HK-01")
	providers := map[string]P.ProxyProvider{}
	// 0 matches
	_, err := buildMatchsGroup("g0", []RawMatchsEntry{{Name: "*NOPE*"}}, proxies, providers)
	assert.Error(t, err)
	// inconsistent types
	proxies2 := testProxiesMap("HK-01", "TW-01")
	_, err = buildMatchsGroup("g1", []RawMatchsEntry{{Name: "*HK*", Type: "select"}, {Name: "*TW*", Type: "url-test"}}, proxies2, providers)
	assert.Error(t, err)
	// default-selected not in result
	_, err = buildMatchsGroup("g2", []RawMatchsEntry{{Name: "*HK*", DefaultSelected: "US-01"}}, testProxiesMap("HK-01"), providers)
	assert.Error(t, err)
}

func TestBuildMatchsGroupSkipsReservedAndGroups(t *testing.T) {
	proxies := testProxiesMap("*") // note: literal name "*"
	providers := map[string]P.ProxyProvider{}
	g, err := buildMatchsGroup("g3", []RawMatchsEntry{{Name: "*"}}, proxies, providers)
	assert.NoError(t, err)
	names := []string{}
	for _, p := range g.Adapter().(*outboundgroup.Selector).Proxies() {
		names = append(names, p.Name())
	}
	assert.NotContains(t, names, "DIRECT")
	assert.NotContains(t, names, "COMPATIBLE")
}
```

(Add imports: `adapter "github.com/metacubex/mihomo/adapter"`, `"github.com/metacubex/mihomo/adapter/outbound"`, `"github.com/metacubex/mihomo/adapter/outboundgroup"`, `C "github.com/metacubex/mihomo/constant"`, `P "github.com/metacubex/mihomo/constant/provider"`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run 'TestBuildMatchsGroup' -v`
Expected: FAIL — undefined `buildMatchsGroup`.

- [ ] **Step 3: Implement**

`isMatchableProxy`: return false if `name` is in the reserved set; return false if `_, ok := p.Adapter().(outboundgroup.ProxyGroup); ok`.

`buildMatchsGroup`:
1. Resolve `groupType` = first entry's `Type` or `"select"`; error if any other entry's non-empty `Type` differs. Validate it is one of `select|url-test|fallback|load-balance`.
2. Collect `matched` names: iterate `proxies` (map), keep `isMatchableProxy(name, p)` where any alternative (split `Name` on `|`) satisfies `wildcard.Match(alt, name)`. Sort the result for deterministic order.
3. Error if `len(matched) == 0`: `fmt.Errorf("multiple-proxy: matchs for %q matched 0 proxies", groupName)`.
4. If `defaultSelected != ""` and not in `matched` → error.
5. Build `mapping := map[string]any{"name": groupName, "type": groupType, "proxies": matched}` and set `mapping["default-selected"] = defaultSelected` when non-empty.
6. `group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, nil, nil)`; on error wrap and return.
7. `p := adapter.NewProxy(group)`; `proxies[groupName] = p`; return `p, nil`. (`ParseProxyGroup` already sets `providersMap[groupName]`.)

Note: `ParseProxyGroup` requires `proxies["COMPATIBLE"]` to exist as the empty-fallback; the real pipeline always seeds it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./config/ -run 'TestBuildMatchsGroup' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add config/multiple_proxy.go config/multiple_proxy_test.go
git commit -m "feat(config): synthesize matchs exit group from proxy name patterns"
```

---

### Task 4: `parseMultipleProxy` orchestration + wiring

**Files:**
- Modify: `config/multiple_proxy.go` (add `buildPortRuleSet`, `buildListenerMapping`, `parseMultipleProxy`)
- Modify: `config/config.go` (call `parseMultipleProxy` in `ParseRawConfig` after `config.SubRules = subRules`, before `parseRules`)
- Test: `config/multiple_proxy_test.go`

**Interfaces:**
- Consumes: `parseRules`, `listener.ParseListener`, everything from Tasks 2–3.
- Produces:
  - `func buildPortRuleSet(rawRules []string, entry RawMultipleProxy, id string) (name string, merged []string)` — returns `("", nil)` when `!entry.EnableGlobalRule && len(entry.Rules) == 0`; otherwise `name = id + "-rules"` and `merged` = base (`rawRules` when `EnableGlobalRule`, else nil) with `entry.Rules` inserted **before the last `MATCH`** rule (append if none). `MATCH` is detected with `RC.ParseRulePayload(line, false)` → `tp == "MATCH"`.
  - `func buildListenerMapping(listenerName string, entry RawMultipleProxy, ltype string, port int, ruleSetName, exitGroup string) map[string]any` — keys `type`,`name`,`port`, plus `rule` (if `ruleSetName != ""`), `mode` (if `entry.Mode != ""`), `fallback-proxy` (if `exitGroup != ""`).
  - `func parseMultipleProxy(cfg *RawConfig, proxies map[string]C.Proxy, providersMap map[string]P.ProxyProvider, ruleProviders map[string]P.RuleProvider, subRules map[string][]C.Rule, listeners map[string]C.InboundListener) error`

- [ ] **Step 1: Write the failing test**

```go
func TestBuildPortRuleSetInsertBeforeMatch(t *testing.T) {
	global := []string{"DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,GLOBAL"}
	entry := RawMultipleProxy{EnableGlobalRule: true, Rules: []string{"DOMAIN-SUFFIX,acl4.ssr,GLOBAL"}}
	name, merged := buildPortRuleSet(global, entry, "mp-0")
	assert.Equal(t, "mp-0-rules", name)
	assert.Equal(t, []string{
		"DOMAIN-SUFFIX,a.com,DIRECT",
		"DOMAIN-SUFFIX,acl4.ssr,GLOBAL",
		"MATCH,GLOBAL",
	}, merged)
}

func TestBuildPortRuleSetAppendWhenNoMatch(t *testing.T) {
	global := []string{"DOMAIN-SUFFIX,a.com,DIRECT"}
	entry := RawMultipleProxy{EnableGlobalRule: true, Rules: []string{"DOMAIN-SUFFIX,b.com,DIRECT"}}
	_, merged := buildPortRuleSet(global, entry, "mp-0")
	assert.Equal(t, []string{"DOMAIN-SUFFIX,a.com,DIRECT", "DOMAIN-SUFFIX,b.com,DIRECT"}, merged)
}

func TestBuildPortRuleSetNoIntent(t *testing.T) {
	name, merged := buildPortRuleSet([]string{"MATCH,GLOBAL"}, RawMultipleProxy{}, "mp-0")
	assert.Equal(t, "", name)
	assert.Nil(t, merged)
}

func TestBuildPortRuleSetOwnRulesOnly(t *testing.T) {
	entry := RawMultipleProxy{Rules: []string{"DOMAIN-SUFFIX,b.com,DIRECT"}}
	name, merged := buildPortRuleSet([]string{"MATCH,GLOBAL"}, entry, "mp-0")
	assert.Equal(t, "mp-0-rules", name)
	assert.Equal(t, []string{"DOMAIN-SUFFIX,b.com,DIRECT"}, merged)
}

func TestParseMultipleProxyPortConflict(t *testing.T) {
	cfg := &RawConfig{
		MixedPort:     7890,
		MultipleProxy: []RawMultipleProxy{{MixedPort: 7890}},
	}
	err := parseMultipleProxy(cfg, map[string]C.Proxy{}, map[string]P.ProxyProvider{}, map[string]P.RuleProvider{}, map[string][]C.Rule{}, map[string]C.InboundListener{})
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run 'TestBuildPortRuleSet|TestParseMultipleProxyPortConflict' -v`
Expected: FAIL — undefined `buildPortRuleSet` / `parseMultipleProxy`.

- [ ] **Step 3: Implement**

`buildPortRuleSet`: as specified above. Locate the last line whose parsed type is `MATCH`; insert `entry.Rules` at that index; else append.

`parseMultipleProxy` — for each entry at index `idx`:
1. `id := multipleProxyID(entry, idx)`; `listenerName := id`.
2. `ltype, port, err := multipleProxyListenerType(entry)`; return err on failure.
3. `validateMultipleProxyMode(entry.Mode)`; return err on failure.
4. Port conflict: build `used, err := collectUsedPorts(cfg)` once before the loop; then per entry, if `used[uint16(port)]` is set → error naming both owners; else record `used[uint16(port)] = "multiple-proxy " + id`.
5. Exit group: if `entry.ProxyGroup != ""` → require `proxies[entry.ProxyGroup]` exists (else error) and `exitGroup = entry.ProxyGroup`. Independently, if `len(entry.Matchs) > 0` → `buildMatchsGroup(id+"-group", entry.Matchs, proxies, providersMap)` (validates even when `proxy-group` wins); if no `proxy-group`, `exitGroup = id + "-group"`. Before building, error if `proxies[id+"-group"]` already exists.
6. Rule set: `ruleName, merged := buildPortRuleSet(cfg.Rule, entry, id)`; if `ruleName != ""` → error if `subRules[ruleName]` already exists; else `compiled, err := parseRules(merged, proxies, ruleProviders, subRules, "multiple-proxy["+id+"]")`; return err; `subRules[ruleName] = compiled`.
7. Listener: `mapping := buildListenerMapping(listenerName, entry, ltype, port, ruleName, exitGroup)`; `l, err := listener.ParseListener(mapping)`; return err; error if `listeners[listenerName]` exists; `listeners[listenerName] = l`.

Then in `config/config.go` `ParseRawConfig`, after `config.SubRules = subRules` insert:
```go
if err = parseMultipleProxy(rawCfg, proxies, providers, ruleProviders, subRules, listeners); err != nil {
	return nil, err
}
```
(`listeners` is already the local from `parseListeners`; the map is the same object as `config.Listeners`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./config/ -run 'TestBuildPortRuleSet|TestParseMultipleProxy' -v`
Expected: PASS. Then run the whole package: `go test ./config/` — expected PASS.

- [ ] **Step 5: Add the reload/leak integration test**

Add a test that runs `parseMultipleProxy` twice against the same `listeners` map: first with one entry, then with the map it returns and an empty `MultipleProxy` slice, asserting the entry's listener is absent from the second result's map (proving a removed entry drops out of the map that `PatchInboundListeners` diffs). Keep it at the map level (do not start sockets).

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./config/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add config/multiple_proxy.go config/config.go config/multiple_proxy_test.go
git commit -m "feat(config): parse multiple-proxy into groups, rule sets and listeners"
```

---

### Task 5: Runtime routing — per-connection mode + fallback

**Files:**
- Modify: `tunnel/tunnel.go` (`resolveMetadata` ~317, `logMetadata` ~635, add helpers near `match`)
- Test: `tunnel/multiple_proxy_test.go` (create)

**Interfaces:**
- Consumes: package globals `proxies map[string]C.Proxy`, `mode TunnelMode`, `T.ModeMapping`, `C.Metadata`.
- Produces:
  - `func effectiveMode(metadata *C.Metadata) TunnelMode` — `T.ModeMapping[metadata.SpecialMode]` when `SpecialMode != ""` and valid; else global `mode`.
  - `func fallbackProxy(metadata *C.Metadata) C.Proxy` — `proxies[metadata.SpecialFallbackProxy]` when set and found; else `proxies["GLOBAL"]`.
  - `func applyFallback(proxy C.Proxy, rule C.Rule, err error, metadata *C.Metadata) (C.Proxy, C.Rule, error)` — when `err == nil && rule == nil`, replace `proxy` with `fallbackProxy(metadata)` if non-nil.

- [ ] **Step 1: Write the failing test**

```go
// tunnel/multiple_proxy_test.go
package tunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func TestEffectiveMode(t *testing.T) {
	oldMode := mode
	defer func() { mode = oldMode }()
	mode = Rule

	assert.Equal(t, Rule, effectiveMode(&C.Metadata{}))
	assert.Equal(t, Global, effectiveMode(&C.Metadata{SpecialMode: "global"}))
	assert.Equal(t, Direct, effectiveMode(&C.Metadata{SpecialMode: "direct"}))
	assert.Equal(t, Rule, effectiveMode(&C.Metadata{SpecialMode: "bogus"})) // invalid → global
}

func TestFallbackProxy(t *testing.T) {
	oldProxies := proxies
	defer func() { proxies = oldProxies }()
	direct := adapter.NewProxy(outbound.NewDirect())
	global := adapter.NewProxy(outbound.NewReject())
	proxies = map[string]C.Proxy{"DIRECT": direct, "GLOBAL": global, "MP-0-group": direct}

	assert.Same(t, direct, fallbackProxy(&C.Metadata{SpecialFallbackProxy: "MP-0-group"}))
	assert.Same(t, global, fallbackProxy(&C.Metadata{}))                       // unset → GLOBAL
	assert.Same(t, global, fallbackProxy(&C.Metadata{SpecialFallbackProxy: "nope"})) // missing → GLOBAL
}

func TestApplyFallback(t *testing.T) {
	oldProxies := proxies
	defer func() { proxies = oldProxies }()
	direct := adapter.NewProxy(outbound.NewDirect())
	proxies = map[string]C.Proxy{"DIRECT": direct, "GLOBAL": direct}

	md := &C.Metadata{SpecialFallbackProxy: "GLOBAL"}
	// rule matched → untouched
	p, r, err := applyFallback(direct, fakeRule{}, nil, md)
	assert.Same(t, direct, p)
	assert.NotNil(t, r)
	assert.NoError(t, err)
	// no rule matched (nil rule) → fallback applied
	p, r, err = applyFallback(direct, nil, nil, md)
	assert.Same(t, direct, p)
	assert.Nil(t, r)
	assert.NoError(t, err)
}
```

Use the existing test-rule helper if one exists; otherwise add a minimal `fakeRule` implementing `C.Rule` (only `Match`, `Adapter`, `RuleType`, `Payload`, `ProviderNames`, `ShouldResolveIP`, `IsDisabled`, `SetDisabled`, `HitCount`, `HitAt`, `MissCount`, `MissAt`). If implementing `C.Rule` is heavy, instead assert the "untouched when rule != nil" case with a real rule built via `rules.ParseRule("DOMAIN-SUFFIX", "x.com", "DIRECT", nil, nil)`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./tunnel/ -run 'TestEffectiveMode|TestFallbackProxy|TestApplyFallback' -v`
Expected: FAIL — undefined `effectiveMode` etc.

- [ ] **Step 3: Implement**

Add near `match` in `tunnel/tunnel.go`:
```go
func effectiveMode(metadata *C.Metadata) TunnelMode {
	if metadata.SpecialMode != "" {
		if m, ok := ModeMapping[metadata.SpecialMode]; ok {
			return m
		}
	}
	return mode
}

func fallbackProxy(metadata *C.Metadata) C.Proxy {
	if metadata.SpecialFallbackProxy != "" {
		if p, ok := proxies[metadata.SpecialFallbackProxy]; ok {
			return p
		}
	}
	return proxies["GLOBAL"]
}

func applyFallback(proxy C.Proxy, rule C.Rule, err error, metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	if err == nil && rule == nil {
		if fb := fallbackProxy(metadata); fb != nil {
			proxy = fb
		}
	}
	return proxy, rule, err
}
```

In `resolveMetadata`, replace the final `switch mode { ... }` with:
```go
switch effectiveMode(metadata) {
case Direct:
	proxy = proxies["DIRECT"]
case Global:
	proxy = fallbackProxy(metadata)
default: // Rule
	proxy, rule, err = match(metadata, helper)
	proxy, rule, err = applyFallback(proxy, rule, err, metadata)
}
```
In `logMetadata`, replace `case mode == Global:` / `case mode == Direct:` with `case effectiveMode(metadata) == Global:` / `== Direct:`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./tunnel/ -run 'TestEffectiveMode|TestFallbackProxy|TestApplyFallback' -v`
Expected: PASS.

- [ ] **Step 5: Full regression + build**

Run: `go build ./... && go test ./config/ ./tunnel/ ./listener/inbound/`
Expected: build clean, all PASS.

- [ ] **Step 6: Commit**

```bash
git add tunnel/tunnel.go tunnel/multiple_proxy_test.go
git commit -m "feat(tunnel): honor per-connection SpecialMode and rule fallback proxy"
```

---

## Self-Review

**1. Spec coverage**

| Spec section | Task |
|---|---|
| §2 config structure / field semantics | Task 2 (types), Task 4 (orchestration) |
| §2 exit priority (proxy-group > matchs > mode fallback) | Task 3 + Task 4 step 5 |
| §2 ruleset semantics (when to build, MATCH insertion, port-scoped) | Task 4 (`buildPortRuleSet`) |
| §2 mode semantics (global ignores rules; rule uses rules w/ fallback; direct) | Task 5 |
| §2 boundary/validation (port conflict, 0 match, type mismatch, default-selected, proxy-group exists, name collision) | Task 2 (port/mode), Task 3 (matchs), Task 4 (proxy-group/collisions) |
| §2 select fixed node (default-selected + runtime switch) | Task 3 (default-selected) |
| §3.2 new seams (metadata + BaseOption + Addition) | Task 1 |
| §3.3 parse pipeline (order after parseProxies/parseListeners) | Task 4 |
| §3.4 runtime routing | Task 5 |
| §3.5 compatibility (empty fields → current path) | Task 1 defaults + Task 5 tests |
| §6 tests | distributed across Tasks 1–5 |

No spec requirement is left without an owning task.

**2. Step scan:** every step is either a named test with assertions, a signature-level implementation step, a `go test`/`go build` verification, or a commit. No "handle edge cases" placeholders. The one place the plan leaves a real choice — the `C.Rule` test double in Task 5 — names the alternative (use a real rule via `rules.ParseRule`) so the implementer picks one deterministically.

**3. Type consistency:** `buildMatchsGroup` (Task 3) and `buildPortRuleSet` / `buildListenerMapping` / `parseMultipleProxy` (Task 4) all use the signatures declared in their Interfaces blocks. `parseMultipleProxy`'s parameter list matches the call site added in `ParseRawConfig`. `effectiveMode`/`fallbackProxy`/`applyFallback` names are identical in Task 5's Interfaces, tests, and implementation. Generated-name convention (`id`, `id+"-group"`, `id+"-rules"`) is fixed once in Global Constraints and used verbatim in Tasks 3–4.

**4. Review Focus:** the five listed input classes are pinned — range-port conflict (Task 2 `TestCollectUsedPortsRange` + Task 4 `TestParseMultipleProxyPortConflict`), MATCH insertion (Task 4 `TestBuildPortRuleSetInsertBeforeMatch`), 0-match error (Task 3 `TestBuildMatchsGroupErrors`), omitted mode inheritance (Task 5 `TestEffectiveMode`), reload drop (Task 4 step 5). No additional uncovered class was found.

**5. Proportion:** the plan is code-block-light — signatures, test bodies, and one algorithm (`buildPortRuleSet` insertion) only; no full function bodies for code the tests already determine.
