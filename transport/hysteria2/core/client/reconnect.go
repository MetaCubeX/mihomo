package client

import (
	"net"
	"sync"

	coreErrs "github.com/metacubex/mihomo/transport/hysteria2/core/errors"
)

// reconnectableClientImpl is a wrapper of Client, which can reconnect when the connection is closed,
// except when the caller explicitly calls Close() to permanently close this client.
type reconnectableClientImpl struct {
	configFunc    func() (*Config, error)           // called before connecting
	connectedFunc func(Client, *HandshakeInfo, int) // called when successfully connected
	client        Client
	count         int
	m             sync.Mutex
	closed        bool // permanent close
}

// NewReconnectableClient creates a reconnectable client.
// If lazy is true, the client will not connect until the first call to TCP() or UDP().
// We use a function for config mainly to delay config evaluation
// (which involves DNS resolution) until the actual connection attempt.
func NewReconnectableClient(configFunc func() (*Config, error), connectedFunc func(Client, *HandshakeInfo, int), lazy bool) (Client, error) {
	rc := &reconnectableClientImpl{
		configFunc:    configFunc,
		connectedFunc: connectedFunc,
	}
	if !lazy {
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

func (rc *reconnectableClientImpl) reconnect() error {
	if rc.client != nil {
		_ = rc.client.Close()
	}
	var info *HandshakeInfo
	config, err := rc.configFunc()
	if err != nil {
		return err
	}
	rc.client, info, err = NewClient(config)
	if err != nil {
		return err
	} else {
		rc.count++
		if rc.connectedFunc != nil {
			rc.connectedFunc(rc, info, rc.count)
		}
		return nil
	}
}

func (rc *reconnectableClientImpl) TCP(addr string) (net.Conn, error) {
	rc.m.Lock()
	defer rc.m.Unlock()
	if rc.closed {
		return nil, coreErrs.ClosedError{}
	}
	if rc.client == nil {
		// No active connection, connect first
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	conn, err := rc.client.TCP(addr)
	if _, ok := err.(coreErrs.ClosedError); ok {
		// Connection closed, reconnect
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
		return rc.client.TCP(addr)
	} else {
		// OK or some other temporary error
		return conn, err
	}
}

func (rc *reconnectableClientImpl) UDP() (HyUDPConn, error) {
	rc.m.Lock()
	defer rc.m.Unlock()
	if rc.closed {
		return nil, coreErrs.ClosedError{}
	}
	if rc.client == nil {
		// No active connection, connect first
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	conn, err := rc.client.UDP()
	if _, ok := err.(coreErrs.ClosedError); ok {
		// Connection closed, reconnect
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
		return rc.client.UDP()
	} else {
		// OK or some other temporary error
		return conn, err
	}
}

func (rc *reconnectableClientImpl) Close() error {
	rc.m.Lock()
	defer rc.m.Unlock()
	rc.closed = true
	if rc.client != nil {
		return rc.client.Close()
	}
	return nil
}
