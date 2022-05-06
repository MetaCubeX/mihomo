package vless

import (
	"github.com/Dreamacro/clash/common/utils"
	"net"

	"github.com/gofrs/uuid"
)

const (
	XRO = "xtls-rprx-origin"
	XRD = "xtls-rprx-direct"
	XRS = "xtls-rprx-splice"

	Version byte = 0 // protocol version. preview version is 0
)

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
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
	Port     uint
}

// Client is vless connection generator
type Client struct {
	uuid     *uuid.UUID
	Addons   *Addons
	XTLSShow bool
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	return newConn(conn, c, dst)
}

// NewClient return Client instance
func NewClient(uuidStr string, addons *Addons, xtlsShow bool) (*Client, error) {
	uid, err := utils.UUIDMap(uuidStr)
	if err != nil {
		return nil, err
	}

	return &Client{
		uuid:     &uid,
		Addons:   addons,
		XTLSShow: xtlsShow,
	}, nil
}
