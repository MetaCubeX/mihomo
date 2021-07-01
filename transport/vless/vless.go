package vless

import (
	"net"

	"github.com/gofrs/uuid"
)

const Version byte = 0 // protocol version. preview version is 0

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

// Config of vless
type Config struct {
	UUID     string
	AlterID  uint16
	Security string
	Port     string
	HostName string
}

// Client is vless connection generator
type Client struct {
	uuid *uuid.UUID
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	return newConn(conn, c.uuid, dst)
}

// NewClient return Client instance
func NewClient(uuidStr string) (*Client, error) {
	uid, err := uuid.FromString(uuidStr)
	if err != nil {
		return nil, err
	}

	return &Client{
		uuid: &uid,
	}, nil
}
