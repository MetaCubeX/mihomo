package vless

import (
	"net"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

const (
	XRO = "xtls-rprx-origin"
	XRD = "xtls-rprx-direct"
	XRS = "xtls-rprx-splice"
	XRV = "xtls-rprx-vision"

	Version byte = 0 // protocol version. preview version is 0
)

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
	CommandMux byte = 3
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	UDP      bool
	AddrType byte
	Addr     []byte
	Port     uint16
	Mux      bool // currently used for XUDP only
}

// Client is vless connection generator
type Client struct {
	uuid   *uuid.UUID
	Addons *Addons
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	return newConn(conn, c, dst)
}

// NewClient return Client instance
func NewClient(uuidStr string, addons *Addons) (*Client, error) {
	uid, err := utils.UUIDMap(uuidStr)
	if err != nil {
		return nil, err
	}

	return &Client{
		uuid:   &uid,
		Addons: addons,
	}, nil
}
