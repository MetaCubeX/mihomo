// quic_pool_test.go —— QuicPool 单测(L4 收尾 · C)。用注入替身 dial/handle 验两铁律:
//
//   - TestQuicPoolReusesOneConn:N 并发 → 1 dial(N openStream 复用同 conn)。
//   - TestQuicPoolSingleFlightColdStart:N 冷启并发首 dial 序列化 → 1 dial(慢路持锁贯穿 dial,
//     其余排队后走快路复用;对照 Rust socks5_quic_pool_reuses_one_conn / single_flight_cold_start)。
//
// 不拨真 QUIC(替身返 nopConn),纯验 pool 编排逻辑。

package transport

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/crypto"
)

// nopConn 测试用零操作 Conn(满足 transport.Conn 接口;pool 编排测试不需真 IO)。
type nopConn struct{}

func (*nopConn) Read([]byte) (int, error)               { return 0, io.EOF }
func (*nopConn) Write(b []byte) (int, error)            { return len(b), nil }
func (*nopConn) Close() error                           { return nil }
func (*nopConn) Exporter() ([crypto.KeyLen]byte, error) { return [crypto.KeyLen]byte{}, nil }
func (*nopConn) ExporterWithLabel(string) ([crypto.KeyLen]byte, error) {
	return [crypto.KeyLen]byte{}, nil
}

// fakePoolHandle 恒活替身(handle 视角):openStream 计数 + 返 nopConn。
type fakePoolHandle struct {
	opens *atomic.Int32
}

func (f *fakePoolHandle) isAlive() bool { return true }
func (f *fakePoolHandle) openStream(context.Context) (Conn, error) {
	f.opens.Add(1)
	return &nopConn{}, nil
}

// TestQuicPoolReusesOneConn:N=4 并发 Dial → 1 dial(conn 复用)+ 4 openStream(N stream 各开)。
// 对照 Rust socks5_quic_pool_reuses_one_conn(N=4 → 1 conn)。
func TestQuicPoolReusesOneConn(t *testing.T) {
	var dials, opens atomic.Int32
	pool := &QuicPool{
		dial: func(context.Context) (pooledHandle, error) {
			dials.Add(1)
			return &fakePoolHandle{opens: &opens}, nil
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
			<-start // 对齐冷启:齐发并发 Dial。
			_, errs[i] = pool.Dial(context.Background())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Dial[%d] 错误: %v", i, err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("dial 次数 = %d, 期望 1(N 复用 1 conn;对照 Rust)", got)
	}
	if got := opens.Load(); got != n {
		t.Errorf("openStream 次数 = %d, 期望 %d(每 Dial 各开 1 stream)", got, n)
	}
}

// TestQuicPoolSingleFlightColdStart:N=8 冷启并发首 dial 序列化 → 1 dial。
// 证明:慢路持锁贯穿阻塞 dial 时,其余 N-1 排队(dial 在飞且持锁),release 后走快路复用 → 单 conn 无 orphan。
// 对照 Rust socks5_quic_pool_single_flight_cold_start。
func TestQuicPoolSingleFlightColdStart(t *testing.T) {
	var dials, opens atomic.Int32
	dialStarted := make(chan struct{})
	release := make(chan struct{})
	dialStartedOnce := sync.Once{}

	pool := &QuicPool{
		dial: func(ctx context.Context) (pooledHandle, error) {
			dials.Add(1)
			dialStartedOnce.Do(func() { close(dialStarted) }) // 首次 dial 起飞信号(只关一次)。
			select {
			case <-release: // 首dial 阻塞在此持锁;其余 N-1 在锁外排队。
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &fakePoolHandle{opens: &opens}, nil
		},
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = pool.Dial(context.Background())
		}(i)
	}

	// 等首 dial 起飞(此时 1 dial 已计数 + 持锁在 release 等待)→ 证明余 N-1 在排队而非各自 dial。
	<-dialStarted
	if got := dials.Load(); got != 1 {
		t.Fatalf("首 dial 起飞时 dial 次数 = %d, 期望 1(其余应排队)", got)
	}
	close(release) // 放行首 dial → 存 handle → 余 N-1 走快路复用。

	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Dial[%d] 错误: %v", i, err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("dial 次数 = %d, 期望 1(冷启 N 并发 single-flight → 单 conn 无 orphan;对照 Rust)", got)
	}
	if got := opens.Load(); got != n {
		t.Errorf("openStream 次数 = %d, 期望 %d", got, n)
	}
}
