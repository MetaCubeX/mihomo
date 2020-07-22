package obfs

import (
	"errors"
	"fmt"
	"strings"
)

var (
	errTLS12TicketAuthIncorrectMagicNumber = errors.New("tls1.2_ticket_auth incorrect magic number")
	errTLS12TicketAuthTooShortData         = errors.New("tls1.2_ticket_auth too short data")
	errTLS12TicketAuthHMACError            = errors.New("tls1.2_ticket_auth hmac verifying failed")
)

// Obfs provides methods for decoding and encoding
type Obfs interface {
	initForConn() Obfs
	GetObfsOverhead() int
	Decode(b []byte) ([]byte, bool, error)
	Encode(b []byte) ([]byte, error)
}

type obfsCreator func(b *Base) Obfs

var obfsList = make(map[string]obfsCreator)

func register(name string, c obfsCreator) {
	obfsList[name] = c
}

// PickObfs returns an obfs of the given name
func PickObfs(name string, b *Base) (Obfs, error) {
	if obfsCreator, ok := obfsList[strings.ToLower(name)]; ok {
		return obfsCreator(b), nil
	}
	return nil, fmt.Errorf("Obfs %s not supported", name)
}
