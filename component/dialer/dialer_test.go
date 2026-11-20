package dialer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func waitDialEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dial event")
	}
}

func assertDialConnUsable(t *testing.T, conn, peer net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = peer.Write([]byte("x")) }()
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil || b[0] != 'x' {
		t.Fatalf("winning connection is unusable: data=%q err=%v", b, err)
	}
}

func TestParallelDialContextCancelsPendingRacers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	started := make(chan struct{})
	canceled := make(chan struct{})
	opt := option{netDialer: NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "192.0.2.1:443" {
			<-started
			return conn, nil
		}
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	})}
	got, err := parallelDialContext(ctx, "tcp", []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
	}, "443", opt)
	if err != nil || got != conn {
		t.Fatalf("got conn=%v err=%v", got, err)
	}
	waitDialEvent(t, canceled)
	if ctx.Err() != nil {
		t.Fatalf("parent context canceled: %v", ctx.Err())
	}
	assertDialConnUsable(t, got, peer)
}

func TestDialContextClosesLateSuccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		dial dialFunc
	}{
		{"parallel", parallelDialContext},
		{"dual stack", func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
			return dualStackDialContext(ctx, parallelDialContext, network, ips, port, opt)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			winner, winnerPeer := net.Pipe()
			defer winner.Close()
			defer winnerPeer.Close()
			loser, loserPeer := net.Pipe()
			defer loser.Close()
			defer loserPeer.Close()
			started := make(chan struct{})
			release := make(chan struct{}, 1)
			defer close(release)
			opt := option{prefer: 4, netDialer: NetDialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
				if address == "192.0.2.1:443" {
					<-started
					return winner, nil
				}
				close(started)
				<-release // Simulate a dial completing successfully despite cancellation.
				return loser, nil
			})}
			got, err := tc.dial(ctx, "tcp", []netip.Addr{
				netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"),
			}, "443", opt)
			if err != nil || got != winner {
				t.Fatalf("got conn=%v err=%v", got, err)
			}
			// Release the late dial only after the winner has been returned.
			release <- struct{}{}
			if err := loserPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err := loserPeer.Read(b[:]); err != io.EOF {
				t.Fatalf("late connection was not closed: %v", err)
			}
			assertDialConnUsable(t, got, winnerPeer)
		})
	}
}

func TestParallelDialContextErrors(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	t.Run("all failed", func(t *testing.T) {
		first, second := errors.New("first dial failed"), errors.New("second dial failed")
		opt := option{netDialer: NetDialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
			if address == "192.0.2.1:443" {
				return nil, first
			}
			return nil, second
		})}
		conn, err := parallelDialContext(context.Background(), "tcp", ips, "443", opt)
		if conn != nil || !errors.Is(err, first) || !errors.Is(err, second) {
			t.Fatalf("got conn=%v err=%v", conn, err)
		}
	})
	t.Run("parent canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		started := make(chan struct{}, 2)
		opt := option{netDialer: NetDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})}
		go func() { <-started; <-started; cancel() }()
		conn, err := parallelDialContext(ctx, "tcp", ips, "443", opt)
		if conn != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("got conn=%v err=%v", conn, err)
		}
	})
}

func TestDualStackDialContextCancelsPendingRacer(t *testing.T) {
	for _, prefer := range []int{4, 6} {
		for _, fallbackWins := range []bool{false, true} {
			t.Run(fmt.Sprintf("prefer%d/fallbackWins=%t", prefer, fallbackWins), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				conn, peer := net.Pipe()
				defer conn.Close()
				defer peer.Close()
				started := make(chan struct{})
				canceled := make(chan struct{})
				dial := func(ctx context.Context, _ string, ips []netip.Addr, _ string, _ option) (net.Conn, error) {
					primary := ips[0].Is4() == (prefer == 4)
					if primary != fallbackWins {
						<-started
						return conn, nil
					}
					close(started)
					<-ctx.Done()
					close(canceled)
					return nil, ctx.Err()
				}
				got, err := dualStackDialContext(ctx, dial, "tcp", []netip.Addr{
					netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"),
				}, "443", option{prefer: prefer})
				if err != nil || got != conn {
					t.Fatalf("got conn=%v err=%v", got, err)
				}
				waitDialEvent(t, canceled)
				if ctx.Err() != nil {
					t.Fatalf("parent context canceled: %v", ctx.Err())
				}
				assertDialConnUsable(t, got, peer)
			})
		}
	}
}
