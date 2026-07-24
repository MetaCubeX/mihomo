// udp_pool_test.go —— 客户端 UDP 池单测(L4 收尾 A)。用注入替身 / 直接喂数据验四铁律(不拨真 QUIC):
//
//   - TestUdpPoolDemuxesByAssocID:reader 按 AssocID 分发,两 ASSOC 各收己方分片不串流。
//   - TestUdpPoolBuffersPendingBeforeRegister:datagram 早于 register 到达 → 落 pending,register 时 drain 照收不丢。
//   - TestUdpPoolRegisterDupFailLoud:重复注册同一 assoc_id → fail-loud(对照 Rust router_register_dup_assoc_fail_loud)。
//   - TestUdpPoolSingleFlightColdStart:N 冷启并发 get → 1 dial(慢路持锁贯穿 dial;对照 QuicPool 单测)。
//
// 对照 Rust datagram_router.rs tests(dispatch/register 逻辑剥离 quinn 直接喂数据)。

package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestState 构造测试用 udpConnState(nil handle / nil dc / 无 reader;dispatch/register 不触 handle/dc)。
func newTestState() *udpConnState {
	return &udpConnState{
		routes:    make(map[uint16]chan inboundFrag),
		pending:   make(map[uint16][]inboundFrag),
		nextAssoc: 1,
		closed:    make(chan struct{}),
	}
}

// TestUdpPoolDemuxesByAssocID 两 ASSOC 各收己方分片,不串流(assoc_id 路由正确性铁证)。
// 对照 Rust router_demuxes_two_assocs。
func TestUdpPoolDemuxesByAssocID(t *testing.T) {
	s := newTestState()
	in1, err := s.register(1)
	if err != nil {
		t.Fatalf("register(1): %v", err)
	}
	in2, err := s.register(2)
	if err != nil {
		t.Fatalf("register(2): %v", err)
	}

	now := time.Now()
	// dispatch 只读 AssocID(header 其余字段 / Addr 不用)→ 用最小 header。
	s.dispatch(DatagramHeader{AssocID: 1}, []byte("one"), now)
	s.dispatch(DatagramHeader{AssocID: 2}, []byte("two"), now)

	f1 := <-in1
	if f1.h.AssocID != 1 || string(f1.frag) != "one" {
		t.Errorf("assoc 1 收到 %+v,期望 AssocID=1 frag=one", f1)
	}
	f2 := <-in2
	if f2.h.AssocID != 2 || string(f2.frag) != "two" {
		t.Errorf("assoc 2 收到 %+v,期望 AssocID=2 frag=two", f2)
	}

	// 不串流:in1 不应再有数据(assoc 2 的分片不进 in1)。
	select {
	case extra := <-in1:
		t.Errorf("assoc 1 串流收到不属于它的分片 %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestUdpPoolBuffersPendingBeforeRegister datagram 早于 register 到达 → 落 pending,register 时 drain 照收不丢。
// 对照 Rust router_buffers_pending_before_register。
func TestUdpPoolBuffersPendingBeforeRegister(t *testing.T) {
	s := newTestState()
	now := time.Now()

	// datagram(assoc 5)在 register(5)之前到达 → 未命中 route → 进 pending。
	s.dispatch(DatagramHeader{AssocID: 5}, []byte("early"), now)

	s.mu.Lock()
	if len(s.pending[5]) != 1 {
		t.Fatalf("pending[5] len = %d, 期望 1(缓冲早到 datagram)", len(s.pending[5]))
	}
	s.mu.Unlock()

	// register(5) → drain pending → inbound 应收到缓冲的分片(不丢)。
	in5, err := s.register(5)
	if err != nil {
		t.Fatalf("register(5): %v", err)
	}
	f := <-in5
	if f.h.AssocID != 5 || string(f.frag) != "early" {
		t.Errorf("drain 后收到 %+v,期望 AssocID=5 frag=early", f)
	}

	// register 后 pending[5] 应清空(已 drain)。
	s.mu.Lock()
	if len(s.pending[5]) != 0 {
		t.Errorf("register drain 后 pending[5] len = %d, 期望 0", len(s.pending[5]))
	}
	s.mu.Unlock()
}

// TestUdpPoolRegisterDupFailLoud 重复注册同一 assoc_id → fail-loud 返 error(不静默覆盖既有 route)。
// 对照 Rust router_register_dup_assoc_fail_loud。
func TestUdpPoolRegisterDupFailLoud(t *testing.T) {
	s := newTestState()
	if _, err := s.register(7); err != nil {
		t.Fatalf("首次 register(7): %v", err)
	}
	if _, err := s.register(7); err == nil {
		t.Fatalf("重复 register(7) 期望 fail-loud error,得 nil")
	}
	// 首次注册的 route 仍在(未被覆盖)。
	s.mu.Lock()
	if _, ok := s.routes[7]; !ok {
		t.Errorf("重复注册后 route[7] 应仍在")
	}
	s.mu.Unlock()
}

// TestUdpPoolSingleFlightColdStart N 冷启并发 get → 1 dial(慢路持锁贯穿 dial,其余排队后走快路复用)。
// 对照 transport.TestQuicPoolSingleFlightColdStart + Rust socks5_quic_pool_single_flight_cold_start。
func TestUdpPoolSingleFlightColdStart(t *testing.T) {
	var dials atomic.Int32
	pool := &udpPool{
		dialState: func(ctx context.Context) (*udpConnState, error) {
			dials.Add(1)
			time.Sleep(20 * time.Millisecond) // 放大竞态:模拟阻塞 dial,期间 N-1 并发 get 排队等锁。
			return newTestState(), nil        // 替身态(closed chan 开 → 活;handle nil → 不触 IsAlive)。
		},
	}

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 对齐冷启:齐发并发 get。
			_, errs[i] = pool.get(context.Background())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("get[%d] 错误: %v", i, err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("dial 次数 = %d, 期望 1(single-flight 冷启 → N get 收敛 1 conn;对照 Rust)", got)
	}
}
