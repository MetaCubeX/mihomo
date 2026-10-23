package muxcool

import (
	"net"
	"testing"
	"time"
)

type mockDisp struct {
	conn    net.Conn
	gotNet  TargetNetwork
	gotAddr Address
	gotPort uint16
}

func (d *mockDisp) DialTarget(n TargetNetwork, a Address, p uint16) (net.Conn, error) {
	d.gotNet, d.gotAddr, d.gotPort = n, a, p
	return d.conn, nil
}

func readFrameT(t *testing.T, c net.Conn) (*FrameMetadata, []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	m, d, err := ReadFrame(c)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	return m, d
}

// Portal 开一个 TCP 子流,数据落地到本地目标,响应回程为 Keep,关闭为 End。
func TestServerWorker_NewTCP_Bidirectional(t *testing.T) {
	portal, bridge := net.Pipe()      // mux 链路
	service, dial := net.Pipe()       // 本地目标(service=测试持有,dial=worker 落地端)
	disp := &mockDisp{conn: dial}

	w := NewServerWorker(bridge, disp, nil)
	go w.Run()
	defer bridge.Close()

	// service 端:收到 "ping" 就回 "pong",然后关闭。
	go func() {
		buf := make([]byte, 64)
		_ = service.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := service.Read(buf)
		if err == nil && string(buf[:n]) == "ping" {
			service.Write([]byte("pong"))
		}
		time.Sleep(50 * time.Millisecond)
		service.Close()
	}()

	// Portal 发 New(SID=1, TCP, 1.2.3.4:80, "ping")。
	m := &FrameMetadata{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
		Address: Address{IP: net.IPv4(1, 2, 3, 4)}, Port: 80}
	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(portal, m, []byte("ping")); err != nil {
		t.Fatal(err)
	}

	// 期望:Keep(SID=1, "pong")。
	rm, rd := readFrameT(t, portal)
	if rm.SessionID != 1 || rm.Status != StatusKeep || string(rd) != "pong" {
		t.Fatalf("unexpected response: sid=%d status=%v data=%q", rm.SessionID, rm.Status, rd)
	}

	// 期望:End(SID=1)。
	em, _ := readFrameT(t, portal)
	if em.SessionID != 1 || em.Status != StatusEnd {
		t.Fatalf("expected End(1), got sid=%d status=%v", em.SessionID, em.Status)
	}

	// dispatcher 收到的 target 正确。
	if disp.gotNet != NetworkTCP || disp.gotPort != 80 || !disp.gotAddr.IP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("dispatcher got wrong target: %v %v :%d", disp.gotNet, disp.gotAddr, disp.gotPort)
	}
}

// 控制子流(target 域 "reverse"):数据经 onControl 回调,不落地。
func TestServerWorker_ControlSubstream(t *testing.T) {
	portal, bridge := net.Pipe()
	got := make(chan []byte, 4)
	disp := &mockDisp{} // 控制流不该触发 dial
	w := NewServerWorker(bridge, disp, func(p []byte) {
		cp := make([]byte, len(p))
		copy(cp, p)
		got <- cp
	})
	go w.Run()
	defer bridge.Close()

	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	// New(SID=2, UDP, "reverse":0)
	newCtl := &FrameMetadata{SessionID: 2, Status: StatusNew, Network: NetworkUDP,
		Address: Address{IsDomain: true, Domain: InternalDomain}, Port: 0}
	if err := WriteFrame(portal, newCtl, nil); err != nil {
		t.Fatal(err)
	}
	// 一条 DRAIN 心跳字节:08 01 9A 06 <len=2> AA BB
	ctl := []byte{0x08, 0x01, 0x9A, 0x06, 0x02, 0xAA, 0xBB}
	if err := WriteData(portal, 2, ctl); err != nil {
		t.Fatal(err)
	}

	select {
	case p := <-got:
		if string(p) != string(ctl) {
			t.Fatalf("control payload mismatch: %x", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("onControl not called")
	}
	if disp.conn != nil {
		t.Fatal("control substream must not dial")
	}
}

// Keep 到未知会话 → Bridge 回一个 End 通知对端关闭。
func TestServerWorker_KeepUnknown_RepliesEnd(t *testing.T) {
	portal, bridge := net.Pipe()
	w := NewServerWorker(bridge, &mockDisp{}, nil)
	go w.Run()
	defer bridge.Close()

	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := WriteData(portal, 99, []byte("orphan")); err != nil {
		t.Fatal(err)
	}
	em, _ := readFrameT(t, portal)
	if em.SessionID != 99 || em.Status != StatusEnd {
		t.Fatalf("expected End(99), got sid=%d status=%v", em.SessionID, em.Status)
	}
}
