// Package nowhere implements the Nowhere nw2 wire protocol.
// Wire specification: NodePassProject/Nowhere, revision 3755592ef37a14682c8f5774b8cd44076810f08f.
package nowhere

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/metacubex/tls"
)

const (
	ALPN                  = "nw2"
	maxFlowID             = 1<<30 - 1
	carrierTLS       byte = 1
	carrierQUIC      byte = 2
	duplex           byte = 0
	open             byte = 1
	attach           byte = 2
	Ready            byte = 0
	InvalidRequest   byte = 1
	MetadataConflict byte = 2
	PairTimeout      byte = 3
	FlowLimit        byte = 4
	DialFailed       byte = 5
	SessionReplaced  byte = 6
	InternalError    byte = 7
)

var errProtocol = errors.New("nowhere: invalid protocol frame")

type hopsKey struct{}

func Hops(ctx context.Context) byte { hops, _ := ctx.Value(hopsKey{}).(byte); return hops }

// ForwardContext carries the remaining Portal forwarding budget into a client
// operation. Local client-originated flows use the default budget of zero.
func ForwardContext(ctx context.Context, incoming byte) (context.Context, error) {
	if incoming > 7 {
		return nil, SetupError(InvalidRequest)
	}
	if incoming == 1 {
		return nil, SetupError(FlowLimit)
	}
	next := incoming - 1
	if incoming == 0 {
		next = 7
	}
	return context.WithValue(ctx, hopsKey{}, next), nil
}

type SetupError byte

func (e SetupError) Error() string {
	names := [...]string{"ready", "invalid request", "metadata conflict", "pair timeout", "flow limit", "dial failed", "session replaced", "internal error"}
	if int(e) >= len(names) {
		return "nowhere: unknown setup result"
	}
	return "nowhere: " + names[e]
}

func authKey(key string) ([32]byte, error) {
	if len(key) < 1 || len(key) > 255 {
		return [32]byte{}, errors.New("nowhere: password must contain 1..255 bytes")
	}
	salt := sha256.Sum256([]byte("nowhere/nw2/auth-root"))
	root := mac(salt[:], []byte(key))
	return mac(root[:], []byte("authentication\x01")), nil
}

func mac(key, data []byte) (out [32]byte) {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	copy(out[:], h.Sum(nil))
	return
}

func authFrame(key [32]byte, carrier byte, exporter []byte, session [16]byte) [32]byte {
	data := append([]byte{carrier}, exporter...)
	data = append(data, session[:]...)
	tag := mac(key[:], data)
	var out [32]byte
	copy(out[:16], session[:])
	copy(out[16:], tag[:16])
	return out
}

func exporter(state tls.ConnectionState) ([]byte, error) {
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ALPN {
		return nil, errors.New("nowhere: TLS 1.3 and ALPN nw2 required")
	}
	return state.ExportKeyingMaterial("EXPORTER-Nowhere-Auth", nil, 32)
}

func readAuth(r io.Reader, key [32]byte, carrier byte, exp []byte) (session [16]byte, err error) {
	var b [32]byte
	if _, err = io.ReadFull(r, b[:]); err != nil {
		return
	}
	copy(session[:], b[:16])
	want := authFrame(key, carrier, exp, session)
	if !hmac.Equal(b[16:], want[16:]) {
		err = errors.New("nowhere: authentication failed")
	}
	return
}

type header struct {
	role, kind, up, down, hops byte
	id                         uint32
}

func (h header) bytes() []byte {
	b := make([]byte, 5)
	b[0] = h.hops<<5 | (h.down-1)<<4 | (h.up-1)<<3 | h.kind<<2 | h.role
	binary.BigEndian.PutUint32(b[1:], h.id)
	return b
}
func readHeader(r io.Reader) (h header, err error) {
	var b [5]byte
	if _, err = io.ReadFull(r, b[:]); err != nil {
		return
	}
	h = header{b[0] & 3, (b[0] >> 2) & 1, 1 + (b[0]>>3)&1, 1 + (b[0]>>4)&1, b[0] >> 5, binary.BigEndian.Uint32(b[1:])}
	if h.role == 3 || h.id == 0 || h.id > maxFlowID {
		err = errProtocol
	}
	return
}
func (h header) validate(carrier byte) error {
	if h.role == duplex && (h.up != h.down || carrier != h.up) || h.role == open && (h.up == h.down || carrier != h.up) || h.role == attach && (h.up == h.down || carrier != h.down) {
		return errProtocol
	}
	return nil
}
func (h header) matches(other header) bool { h.role = 0; other.role = 0; return h == other }

func targetBytes(address string) ([]byte, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, errors.New("nowhere: invalid target port")
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if !validDomain(host) {
			return nil, errors.New("nowhere: invalid target domain")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return append(b, byte(p>>8), byte(p)), nil
}
func validDomain(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func readTarget(r io.Reader) (string, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return "", err
	}
	n := 0
	switch typ[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		n = int(l[0])
	default:
		return "", errProtocol
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	host := string(b[:n])
	if typ[0] != 3 {
		host = net.IP(b[:n]).String()
	} else if !validDomain(host) {
		return "", errProtocol
	}
	p := binary.BigEndian.Uint16(b[n:])
	if p == 0 {
		return "", errProtocol
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p))), nil
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func readResult(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] > InternalError {
		return fmt.Errorf("%w: setup result %d", errProtocol, b[0])
	}
	if b[0] != Ready {
		return SetupError(b[0])
	}
	return nil
}
