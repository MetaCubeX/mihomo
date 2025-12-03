package tuic

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/quic-go"

	list "github.com/bahlo/generic-list-go"
)

type PoolClient struct {
	newClientOptionV4 *ClientOptionV4
	newClientOptionV5 *ClientOptionV5

	dialHelper      *poolDialHelper
	tcpClients      list.List[Client]
	tcpClientsMutex sync.Mutex
	udpClients      list.List[Client]
	udpClientsMutex sync.Mutex
}

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	conn, err := t.getClient(false).DialContext(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		conn, err = t.newClient(false).DialContext(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	pc, err := t.getClient(true).ListenPacket(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		pc, err = t.newClient(true).ListenPacket(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

// poolDialHelper is a helper for dialFn
// using a standalone struct to let finalizer working
type poolDialHelper struct {
	dialFn     DialFunc
	dialResult atomic.Pointer[dialResult]
}

type dialResult struct {
	transport *quic.Transport
	addr      net.Addr
}

func (t *poolDialHelper) dial(ctx context.Context) (transport *quic.Transport, addr net.Addr, err error) {
	if dr := t.dialResult.Load(); dr != nil {
		return dr.transport, dr.addr, nil
	}

	transport, addr, err = t.dialFn(ctx)
	if err != nil {
		return nil, nil, err
	}

	if _, ok := transport.Conn.(*net.UDPConn); ok { // only cache the system's UDPConn
		transport.SetSingleUse(false) // don't close transport in each dial

		dr := &dialResult{transport: transport, addr: addr}
		t.dialResult.Store(dr)
	}

	return transport, addr, err
}

func (t *poolDialHelper) forceClose() {
	if dr := t.dialResult.Swap(nil); dr != nil {
		transport := dr.transport
		if transport != nil {
			_ = transport.Close()
		}
	}
}

func (t *PoolClient) newClient(udp bool) (client Client) {
	clients := &t.tcpClients
	clientsMutex := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		clientsMutex = &t.udpClientsMutex
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	dialHelper := t.dialHelper
	if t.newClientOptionV4 != nil {
		client = NewClientV4(t.newClientOptionV4, udp, dialHelper.dial)
	} else {
		client = NewClientV5(t.newClientOptionV5, udp, dialHelper.dial)
	}

	client.SetLastVisited(time.Now())

	clients.PushFront(client)
	return client
}

func (t *PoolClient) getClient(udp bool) Client {
	clients := &t.tcpClients
	clientsMutex := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		clientsMutex = &t.udpClientsMutex
	}
	var bestClient Client

	func() {
		clientsMutex.Lock()
		defer clientsMutex.Unlock()
		for it := clients.Front(); it != nil; {
			client := it.Value
			if client == nil {
				next := it.Next()
				clients.Remove(it)
				it = next
				continue
			}
			if bestClient == nil {
				bestClient = client
			} else {
				if client.OpenStreams() < bestClient.OpenStreams() {
					bestClient = client
				}
			}
			it = it.Next()
		}
		for it := clients.Front(); it != nil; {
			client := it.Value
			if client != bestClient && client.OpenStreams() == 0 && time.Now().Sub(client.LastVisited()) > 30*time.Minute {
				client.Close()
				next := it.Next()
				clients.Remove(it)
				it = next
				continue
			}
			it = it.Next()
		}
	}()

	if bestClient == nil {
		return t.newClient(udp)
	} else {
		bestClient.SetLastVisited(time.Now())
		return bestClient
	}
}

func NewPoolClientV4(clientOption *ClientOptionV4, dialFn DialFunc) *PoolClient {
	p := &PoolClient{
		dialHelper: &poolDialHelper{dialFn: dialFn},
	}
	newClientOption := *clientOption
	p.newClientOptionV4 = &newClientOption
	runtime.SetFinalizer(p, closeClientPool)
	log.Debugln("New TuicV4 PoolClient at %p", p)
	return p
}

func NewPoolClientV5(clientOption *ClientOptionV5, dialFn DialFunc) *PoolClient {
	p := &PoolClient{
		dialHelper: &poolDialHelper{dialFn: dialFn},
	}
	newClientOption := *clientOption
	p.newClientOptionV5 = &newClientOption
	runtime.SetFinalizer(p, closeClientPool)
	log.Debugln("New TuicV5 PoolClient at %p", p)
	return p
}

func closeClientPool(client *PoolClient) {
	log.Debugln("Close Tuic PoolClient at %p", client)
	client.dialHelper.forceClose()
}
