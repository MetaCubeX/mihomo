//go:build !no_easytier

package outbound

import (
	"testing"

	corehost "github.com/easytier/easytier/easytier-go"
	apiinstance "github.com/easytier/easytier/easytier-go/proto/api/instance"
)

func TestEasyTierHasPeerConn(t *testing.T) {
	if easyTierHasPeerConn(nil) {
		t.Fatal("nil peers should be disconnected")
	}
	if easyTierHasPeerConn([]*corehost.PeerInfo{nil, {}}) {
		t.Fatal("peers without connections should be disconnected")
	}
	if !easyTierHasPeerConn([]*corehost.PeerInfo{
		{},
		{Conns: []*apiinstance.PeerConnInfo{{}}},
	}) {
		t.Fatal("a peer with a connection should be connected")
	}
}
