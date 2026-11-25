//go:build go1.25

package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// The main module preserves pre-Go-1.23 timer-channel defaults. A synctest
// bubble requires synchronous timer channels; scope this override to these
// serial tests and restore it before other tests. Production is unaffected.
func lifecycleHealthTimers(t *testing.T) {
	t.Helper()
	value := os.Getenv("GODEBUG")
	if value != "" {
		value += ","
	}
	t.Setenv("GODEBUG", value+"asynctimerchan=0")
}

type lifecycleHealthProvider struct {
	P.ProxyProvider
	proxies []C.Proxy
	probes  atomic.Int32
	probe   func()
}

func (p *lifecycleHealthProvider) Version() uint32            { return 1 }
func (p *lifecycleHealthProvider) Proxies() []C.Proxy         { return p.proxies }
func (p *lifecycleHealthProvider) Touch()                     {}
func (p *lifecycleHealthProvider) VehicleType() P.VehicleType { return P.Inline }

func (p *lifecycleHealthProvider) HealthCheck() {
	p.probes.Add(1)
	if p.probe != nil {
		p.probe()
	}
}

type lifecycleHealthLeaf struct {
	*outbound.Base
	dial func(context.Context) (C.Conn, error)
}

func (p *lifecycleHealthLeaf) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	return p.dial(ctx)
}

type lifecycleHealthConn struct {
	C.Conn
	failure error
}

func (c *lifecycleHealthConn) NeedHandshake() bool { return true }
func (c *lifecycleHealthConn) Write(data []byte) (int, error) {
	if c.failure != nil {
		return 0, c.failure
	}
	return len(data), nil
}
func (c *lifecycleHealthConn) WriteBuffer(data *buf.Buffer) error { data.Release(); return c.failure }
func (c *lifecycleHealthConn) Close() error                       { return nil }
func (c *lifecycleHealthConn) Chains() C.Chain                    { return C.Chain{"synthetic-leaf"} }
func (c *lifecycleHealthConn) ProviderChains() C.Chain            { return nil }
func (c *lifecycleHealthConn) AppendToChains(C.ProxyAdapter)      {}
func (c *lifecycleHealthConn) RemoteDestination() string          { return "local.invalid" }

type lifecycleHealthFixture struct {
	proxy    C.Proxy
	base     *GroupBase
	provider *lifecycleHealthProvider
}

func lifecycleHealthGroup(t *testing.T, kind string, child C.Proxy) lifecycleHealthFixture {
	t.Helper()
	p := &lifecycleHealthProvider{proxies: []C.Proxy{child}}
	option := GroupCommonOption{Name: "lifecycle-" + kind, MaxFailedTimes: 2, TestTimeout: 1000}
	providers := []P.ProxyProvider{p}
	var group C.ProxyAdapter
	var base *GroupBase
	var err error
	switch kind {
	case "fallback":
		var g *Fallback
		g, err = NewFallback(option, FallbackOption{}, child, providers)
		if g != nil {
			base = g.GroupBase
		}
		group = g
	case "urltest":
		var g *URLTest
		g, err = NewURLTest(option, URLTestOption{}, child, providers)
		if g != nil {
			base = g.GroupBase
		}
		group = g
	case "loadbalance":
		var g *LoadBalance
		g, err = NewLoadBalance(option, LoadBalanceOption{Strategy: "round-robin"}, child, providers)
		if g != nil {
			base = g.GroupBase
		}
		group = g
	default:
		t.Fatal(kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return lifecycleHealthFixture{proxy: adapter.NewProxy(group), base: base, provider: p}
}
func lifecycleHealthCount(g *GroupBase) int {
	g.failedTestMux.Lock()
	defer g.failedTestMux.Unlock()
	return g.failedTimes
}
func lifecycleHealthMetadata() *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("203.0.113.80"), DstPort: 443}
}
func lifecycleHealthProxy(dial func(context.Context) (C.Conn, error)) C.Proxy {
	return adapter.NewProxy(&lifecycleHealthLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "synthetic-leaf", Type: C.Trojan}), dial: dial})
}

// synctest.Wait drains runnable accounting and callback work before negative
// assertions. No real provider, network probe, or short sleep is used.
func TestLifecycleGroupTCPFailureAttribution(t *testing.T) {
	lifecycleHealthTimers(t)
	for _, kind := range []string{"fallback", "urltest", "loadbalance"} {
		for _, stage := range []string{"dial", "write", "write-buffer"} {
			for _, canceled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/canceled%v", kind, stage, canceled), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						leaf := lifecycleHealthProxy(func(context.Context) (C.Conn, error) {
							if stage == "dial" {
								if canceled {
									cancel()
								}
								return nil, net.ErrClosed
							}
							return &lifecycleHealthConn{failure: net.ErrClosed}, nil
						})
						g := lifecycleHealthGroup(t, kind, leaf)
						for attempt := 0; attempt < 2; attempt++ {
							conn, err := g.proxy.DialContext(ctx, lifecycleHealthMetadata())
							if stage != "dial" {
								if err != nil {
									t.Fatal(err)
								}
								if canceled {
									cancel()
								}
								if stage == "write" {
									_, err = conn.Write([]byte("request"))
								} else {
									err = conn.WriteBuffer(buf.As([]byte("request")))
								}
								_ = conn.Close()
							}
							if !errors.Is(err, net.ErrClosed) {
								t.Fatal("fixture did not return raw socket error", err)
							}
							synctest.Wait()
							if canceled {
								if lifecycleHealthCount(g.base) != 0 || g.provider.probes.Load() != 0 {
									t.Fatal("client cancellation triggered node failure accounting")
								}
							} else if attempt == 0 {
								if lifecycleHealthCount(g.base) != 1 || g.provider.probes.Load() != 0 {
									t.Fatal("real first failure not accounted")
								}
							} else if g.provider.probes.Load() != 1 {
								t.Fatal("real repeated failures did not trigger health check")
							}
						}
					})
				})
			}
		}
	}
}

// Concurrent successful first writes and failed dials enter the same public
// group paths as independent requests. Keep this fixture compatible with Alpha
// so its race result can be compared without candidate-only accounting helpers.
func TestLifecycleGroupConcurrentPublicPaths(t *testing.T) {
	lifecycleHealthTimers(t)
	synctest.Test(t, func(t *testing.T) {
		var calls, successes, failures atomic.Int32
		leaf := lifecycleHealthProxy(func(context.Context) (C.Conn, error) {
			if calls.Add(1)%2 == 0 {
				return nil, net.ErrClosed
			}
			return &lifecycleHealthConn{}, nil
		})
		g := lifecycleHealthGroup(t, "fallback", leaf)
		var workers sync.WaitGroup
		for i := 0; i < 64; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for j := 0; j < 8; j++ {
					conn, err := g.proxy.DialContext(context.Background(), lifecycleHealthMetadata())
					if err != nil {
						failures.Add(1)
						continue
					}
					if _, err = conn.Write([]byte("request")); err != nil {
						t.Error(err)
					}
					successes.Add(1)
					_ = conn.Close()
				}
			}()
		}
		workers.Wait()
		synctest.Wait()
		if successes.Load() == 0 || failures.Load() == 0 {
			t.Fatal("concurrent public paths did not exercise both outcomes")
		}
	})
}

func TestLifecycleGroupSuccessfulFirstWrite(t *testing.T) {
	lifecycleHealthTimers(t)
	for _, kind := range []string{"fallback", "urltest", "loadbalance"} {
		for _, buffered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/buffered%v", kind, buffered), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					raw := &lifecycleHealthConn{}
					leaf := lifecycleHealthProxy(func(context.Context) (C.Conn, error) { return raw, nil })
					g := lifecycleHealthGroup(t, kind, leaf)
					g.base.failedTimes = 1
					conn, err := g.proxy.DialContext(context.Background(), lifecycleHealthMetadata())
					if err != nil {
						t.Fatal(err)
					}
					if buffered {
						err = conn.WriteBuffer(buf.As([]byte("ok")))
					} else {
						_, err = conn.Write([]byte("ok"))
					}
					if err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if lifecycleHealthCount(g.base) != 0 {
						t.Fatal("successful handshake did not reset failures")
					}
					raw.failure = net.ErrClosed
					_, _ = conn.Write([]byte("later"))
					_ = conn.Close()
					synctest.Wait()
					if lifecycleHealthCount(g.base) != 0 || g.provider.probes.Load() != 0 {
						t.Fatal("post-handshake write repeated first-write accounting")
					}
				})
			})
		}
	}
}

func TestLifecycleGroupFailureContextOrdering(t *testing.T) {
	lifecycleHealthTimers(t)
	for _, order := range []string{"cancel-first", "deadline-first", "alive-internal-cancel", "attributed-before-cancel"} {
		t.Run(order, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := NewGroupBase(GroupBaseOption{Name: order, MaxFailedTimes: 2})
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				failure := error(net.ErrClosed)
				switch order {
				case "cancel-first":
					cancel()
					time.Sleep(2 * time.Second)
				case "deadline-first":
					time.Sleep(2 * time.Second)
					cancel()
				case "alive-internal-cancel":
					failure = context.Canceled
				case "attributed-before-cancel":
					g.failedTestMux.Lock()
				}
				g.onTCPDialFailed(ctx, C.Trojan, failure, func() { t.Error("single failure unexpectedly triggered health check") })
				if order == "attributed-before-cancel" {
					cancel()
					g.failedTestMux.Unlock()
				}
				synctest.Wait()
				expected := 1
				if order == "cancel-first" {
					expected = 0
				}
				if got := lifecycleHealthCount(g); got != expected {
					t.Fatalf("failure count %d, want %d", got, expected)
				}
			})
		})
	}
}

func TestLifecycleGroupFailureExemptionsAndRefused(t *testing.T) {
	lifecycleHealthTimers(t)
	synctest.Test(t, func(t *testing.T) {
		g := NewGroupBase(GroupBaseOption{Name: "exempt", MaxFailedTimes: 2})
		for _, kind := range []C.AdapterType{C.Direct, C.Compatible, C.Reject, C.Pass, C.RejectDrop} {
			g.onTCPDialFailed(context.Background(), kind, net.ErrClosed, func() { t.Error("exempt type probed") })
		}
		g.onTCPDialFailed(context.Background(), C.Trojan, fmt.Errorf("wrapped: %w", C.ErrNotSupport), func() { t.Error("unsupported protocol probed") })
		synctest.Wait()
		if lifecycleHealthCount(g) != 0 {
			t.Fatal("exempt failure counted")
		}
		var probes atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		g.onTCPDialFailed(ctx, C.Trojan, errors.New("dial: connection refused"), func() { probes.Add(1) })
		synctest.Wait()
		if probes.Load() != 0 {
			t.Fatal("canceled refusal probed")
		}
		g.onTCPDialFailed(context.Background(), C.Trojan, errors.New("dial: connection refused"), func() { probes.Add(1) })
		synctest.Wait()
		if probes.Load() != 1 {
			t.Fatal("live connection-refused fast path lost")
		}
	})
}

func TestLifecycleNestedGroupsKeepFailureAttribution(t *testing.T) {
	lifecycleHealthTimers(t)
	for _, stage := range []string{"dial", "write", "write-buffer"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/canceled%v", stage, canceled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					leaf := lifecycleHealthProxy(func(context.Context) (C.Conn, error) {
						if stage == "dial" {
							if canceled {
								cancel()
							}
							return nil, net.ErrClosed
						}
						return &lifecycleHealthConn{failure: net.ErrClosed}, nil
					})
					inner := lifecycleHealthGroup(t, "fallback", leaf)
					outer := lifecycleHealthGroup(t, "urltest", inner.proxy)
					conn, err := outer.proxy.DialContext(ctx, lifecycleHealthMetadata())
					if stage != "dial" {
						if err != nil {
							t.Fatal(err)
						}
						if canceled {
							cancel()
						}
						if stage == "write" {
							_, err = conn.Write([]byte("request"))
						} else {
							err = conn.WriteBuffer(buf.As([]byte("request")))
						}
						_ = conn.Close()
					}
					if !errors.Is(err, net.ErrClosed) {
						t.Fatal(err)
					}
					synctest.Wait()
					expected := 1
					if canceled {
						expected = 0
					}
					if lifecycleHealthCount(inner.base) != expected || lifecycleHealthCount(outer.base) != expected {
						t.Fatal("nested layers changed attribution")
					}
					if inner.provider.probes.Load() != 0 || outer.provider.probes.Load() != 0 {
						t.Fatal("single nested failure triggered probe")
					}
				})
			})
		}
	}
}

func TestLifecycleGroupConcurrentHealthAccounting(t *testing.T) {
	lifecycleHealthTimers(t)
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		defer func() {
			select {
			case <-gate:
			default:
				close(gate)
			}
		}()
		var active, peak atomic.Int32
		p := &lifecycleHealthProvider{probe: func() {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			<-gate
		}}
		g := NewGroupBase(GroupBaseOption{Name: "concurrent", MaxFailedTimes: 2, Providers: []P.ProxyProvider{p}})
		go g.healthCheck()
		synctest.Wait()
		if active.Load() != 1 || !g.failedTesting.Load() {
			t.Fatal("probe did not enter held fixture")
		}
		for i := 0; i < 32; i++ {
			go g.healthCheck()
			go g.onDialSuccess()
			g.onTCPDialFailed(context.Background(), C.Trojan, net.ErrClosed, g.healthCheck)
		}
		synctest.Wait()
		if p.probes.Load() != 1 || peak.Load() != 1 {
			t.Fatal("concurrent health checks not coalesced")
		}
		close(gate)
		for i := 0; i < 32; i++ {
			go g.onDialSuccess()
			g.onTCPDialFailed(context.Background(), C.Trojan, net.ErrClosed, g.healthCheck)
		}
		synctest.Wait()
		if active.Load() != 0 || g.failedTesting.Load() || peak.Load() != 1 {
			t.Fatal("health accounting did not settle")
		}
	})
}
