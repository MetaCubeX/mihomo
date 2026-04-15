package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	list "github.com/bahlo/generic-list-go"
)

type PoolClient struct {
	newClientOptionV4 *ClientOptionV4
	newClientOptionV5 *ClientOptionV5

	dialFn          DialFunc
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

func (t *PoolClient) newClient(udp bool) (client Client) {
	clients := &t.tcpClients
	clientsMutex := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		clientsMutex = &t.udpClientsMutex
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	if t.newClientOptionV4 != nil {
		client = NewClientV4(t.newClientOptionV4, udp, t.dialFn)
	} else {
		client = NewClientV5(t.newClientOptionV5, udp, t.dialFn)
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
		dialFn: dialFn,
	}
	newClientOption := *clientOption
	p.newClientOptionV4 = &newClientOption
	return p
}

func NewPoolClientV5(clientOption *ClientOptionV5, dialFn DialFunc) *PoolClient {
	p := &PoolClient{
		dialFn: dialFn,
	}
	newClientOption := *clientOption
	p.newClientOptionV5 = &newClientOption
	return p
}
