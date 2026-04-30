package sniffer

import (
	"encoding/binary"
	"errors"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
)

// https://datatracker.ietf.org/doc/html/rfc8489
const (
	stunHeaderSize  = 20
	stunMagicCookie = 0x2112A442
)

var (
	errNotSTUN = errors.New("not STUN message")
)

var _ sniffer.Sniffer = (*STUNSniffer)(nil)

type STUNSniffer struct {
	*BaseSniffer
}

func NewSTUNSniffer(snifferConfig SnifferConfig) (*STUNSniffer, error) {
	return &STUNSniffer{
		BaseSniffer: NewBaseSniffer(snifferConfig.Ports, C.UDP),
	}, nil
}

func (s *STUNSniffer) Protocol() string {
	return "stun"
}

func (s *STUNSniffer) SupportNetwork() C.NetWork {
	return C.UDP
}

func (s *STUNSniffer) SniffData(b []byte) (string, error) {
	if err := detectSTUN(b); err != nil {
		return "", err
	}

	return "", nil
}

func detectSTUN(b []byte) error {
	if len(b) < stunHeaderSize {
		return errNotSTUN
	}

	if b[0]&0xC0 != 0x00 {
		return errNotSTUN
	}

	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return errNotSTUN
	}

	msgLen := binary.BigEndian.Uint16(b[2:4])
	if msgLen%4 != 0 {
		return errNotSTUN
	}

	return nil
}
