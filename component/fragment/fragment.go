// Package fragment splits the first packets written to a TCP connection into
// small pieces, like the fragment feature of xray's freedom outbound.
// It is mostly used to hide the SNI in the TLS ClientHello from DPI.
package fragment

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/randv2"
)

const (
	DefaultPackets  = "tlshello"
	DefaultLength   = "100-200"
	DefaultInterval = "10-20"

	tlsRecordHeaderLen  = 5
	tlsRecordHandshake  = 22
	maxInterval         = 10 * 1000 // milliseconds
	maxFragmentedWrites = 1 << 16
)

type Config struct {
	// TLSHello only fragments the first write when it is a TLS handshake record,
	// each fragment is sent as its own TLS record.
	TLSHello bool
	// PacketsFrom and PacketsTo are the range of writes (starting from 1) to fragment
	// when TLSHello is false.
	PacketsFrom, PacketsTo uint32
	// LengthMin and LengthMax are the size of each fragment in bytes.
	LengthMin, LengthMax int
	// IntervalMin and IntervalMax are the delay between fragments in milliseconds.
	IntervalMin, IntervalMax int
}

func parseRange(name, s string, min, max int) (from, to int, err error) {
	a, b, isRange := strings.Cut(strings.TrimSpace(s), "-")
	from, err = strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid fragment %s %q", name, s)
	}
	to = from
	if isRange {
		to, err = strconv.Atoi(strings.TrimSpace(b))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid fragment %s %q", name, s)
		}
	}
	if from > to || from < min || to > max {
		return 0, 0, fmt.Errorf("invalid fragment %s %q: must be in %d-%d", name, s, min, max)
	}
	return from, to, nil
}

// ParseConfig parses the user facing options, empty strings mean the default value.
func ParseConfig(packets, length, interval string) (*Config, error) {
	if packets == "" {
		packets = DefaultPackets
	}
	if length == "" {
		length = DefaultLength
	}
	if interval == "" {
		interval = DefaultInterval
	}

	config := &Config{}
	var err error
	if strings.EqualFold(strings.TrimSpace(packets), "tlshello") {
		config.TLSHello = true
	} else {
		var from, to int
		from, to, err = parseRange("packets", packets, 1, maxFragmentedWrites)
		if err != nil {
			return nil, err
		}
		config.PacketsFrom, config.PacketsTo = uint32(from), uint32(to)
	}
	config.LengthMin, config.LengthMax, err = parseRange("length", length, 1, 1<<14)
	if err != nil {
		return nil, err
	}
	config.IntervalMin, config.IntervalMax, err = parseRange("interval", interval, 0, maxInterval)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func randBetween(min, max int) int {
	if max <= min {
		return min
	}
	return min + randv2.IntN(max-min+1)
}

type Conn struct {
	N.ExtendedConn
	config *Config

	access sync.Mutex
	count  uint32
	done   atomic.Bool
}

// NewConn returns a conn fragmenting the first writes of c following config.
func NewConn(c net.Conn, config *Config) *Conn {
	return &Conn{ExtendedConn: N.NewExtendedConn(c), config: config}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.done.Load() {
		return c.ExtendedConn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.count++

	if c.config.TLSHello {
		c.done.Store(true)
		if c.count != 1 || len(b) <= tlsRecordHeaderLen || b[0] != tlsRecordHandshake {
			return c.ExtendedConn.Write(b)
		}
		recordLen := tlsRecordHeaderLen + int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < recordLen {
			return c.ExtendedConn.Write(b)
		}
		if err := c.writeTLSRecords(b[:recordLen]); err != nil {
			return 0, err
		}
		if len(b) > recordLen {
			if _, err := c.ExtendedConn.Write(b[recordLen:]); err != nil {
				return 0, err
			}
		}
		return len(b), nil
	}

	if c.count >= c.config.PacketsTo {
		c.done.Store(true)
	}
	if c.count < c.config.PacketsFrom || c.count > c.config.PacketsTo {
		return c.ExtendedConn.Write(b)
	}
	for n := 0; n < len(b); {
		size := randBetween(c.config.LengthMin, c.config.LengthMax)
		if size > len(b)-n {
			size = len(b) - n
		}
		if _, err := c.ExtendedConn.Write(b[n : n+size]); err != nil {
			return n, err
		}
		n += size
		if n < len(b) {
			c.sleep()
		}
	}
	return len(b), nil
}

// writeTLSRecords re-frames one TLS record into many smaller ones
func (c *Conn) writeTLSRecords(record []byte) error {
	header, data := record[:3], record[tlsRecordHeaderLen:]
	noDelay := c.config.IntervalMax == 0
	var merged []byte
	for len(data) > 0 {
		size := randBetween(c.config.LengthMin, c.config.LengthMax)
		if size > len(data) {
			size = len(data)
		}
		fragment := make([]byte, 0, tlsRecordHeaderLen+size)
		fragment = append(fragment, header...)
		fragment = binary.BigEndian.AppendUint16(fragment, uint16(size))
		fragment = append(fragment, data[:size]...)
		data = data[size:]

		if noDelay { // without delay there is no point in doing many syscalls
			merged = append(merged, fragment...)
			continue
		}
		if _, err := c.ExtendedConn.Write(fragment); err != nil {
			return err
		}
		if len(data) > 0 {
			c.sleep()
		}
	}
	if noDelay {
		_, err := c.ExtendedConn.Write(merged)
		return err
	}
	return nil
}

func (c *Conn) sleep() {
	if ms := randBetween(c.config.IntervalMin, c.config.IntervalMax); ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

func (c *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if c.done.Load() {
		return c.ExtendedConn.WriteBuffer(buffer)
	}
	defer buffer.Release()
	_, err := c.Write(buffer.Bytes())
	return err
}

func (c *Conn) Upstream() any {
	return c.ExtendedConn
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.done.Load()
}

type fragmentDialer struct {
	C.Dialer
	config *Config
}

// NewDialer wraps dialer so that every TCP connection it creates is fragmented.
func NewDialer(dialer C.Dialer, config *Config) C.Dialer {
	return &fragmentDialer{Dialer: dialer, config: config}
}

func (d *fragmentDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(network, "tcp") {
		return NewConn(conn, d.config), nil
	}
	return conn, nil
}
