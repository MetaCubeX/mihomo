package fragment

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordConn records every write it gets
type recordConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func clientHello(size int) []byte {
	record := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(record[3:], uint16(size))
	for i := 0; i < size; i++ {
		record = append(record, byte(i))
	}
	return record
}

// reassemble parses TLS records and returns their concatenated payload
func reassemble(t *testing.T, stream []byte, maxLen int) (payload []byte, records int) {
	r := bytes.NewReader(stream)
	for r.Len() > 0 {
		var header [5]byte
		_, err := io.ReadFull(r, header[:])
		require.NoError(t, err)
		require.Equal(t, []byte{22, 3, 1}, header[:3])
		size := int(binary.BigEndian.Uint16(header[3:]))
		require.LessOrEqual(t, size, maxLen)
		data := make([]byte, size)
		_, err = io.ReadFull(r, data)
		require.NoError(t, err)
		payload = append(payload, data...)
		records++
	}
	return
}

func TestParseConfig(t *testing.T) {
	config, err := ParseConfig("", "", "")
	require.NoError(t, err)
	assert.Equal(t, &Config{TLSHello: true, LengthMin: 100, LengthMax: 200, IntervalMin: 10, IntervalMax: 20}, config)

	config, err = ParseConfig("1-3", "5", "0")
	require.NoError(t, err)
	assert.Equal(t, &Config{PacketsFrom: 1, PacketsTo: 3, LengthMin: 5, LengthMax: 5}, config)

	for _, bad := range [][3]string{
		{"hello", "", ""}, {"0-3", "", ""}, {"3-1", "", ""},
		{"", "0", ""}, {"", "20-10", ""}, {"", "abc", ""},
		{"", "", "-1"}, {"", "", "1-x"}, {"", "", "999999"},
	} {
		_, err = ParseConfig(bad[0], bad[1], bad[2])
		assert.Error(t, err, "%v", bad)
	}
}

func TestTLSHello(t *testing.T) {
	for _, interval := range []string{"0", "0-1"} {
		config, err := ParseConfig("tlshello", "10-20", interval)
		require.NoError(t, err)
		rc := &recordConn{}
		conn := NewConn(rc, config)

		hello := clientHello(517)
		n, err := conn.Write(append(append([]byte(nil), hello...), "extra"...))
		require.NoError(t, err)
		assert.Equal(t, len(hello)+5, n)

		// the trailing data is sent untouched after the records
		last := rc.writes[len(rc.writes)-1]
		assert.Equal(t, "extra", string(last))
		payload, records := reassemble(t, bytes.Join(rc.writes[:len(rc.writes)-1], nil), 20)
		assert.Equal(t, hello[5:], payload)
		assert.GreaterOrEqual(t, records, 517/20)
		if interval == "0" {
			assert.Len(t, rc.writes, 2) // merged in one write
		} else {
			assert.Len(t, rc.writes, records+1)
		}

		// following writes are not touched anymore
		assert.True(t, conn.WriterReplaceable())
		_, err = conn.Write(hello)
		require.NoError(t, err)
		assert.Equal(t, hello, rc.writes[len(rc.writes)-1])
	}
}

func TestTLSHelloNotTLS(t *testing.T) {
	config, err := ParseConfig("tlshello", "1", "0")
	require.NoError(t, err)
	for _, data := range [][]byte{
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{22, 3, 1},
		clientHello(100)[:50], // truncated record
	} {
		rc := &recordConn{}
		conn := NewConn(rc, config)
		_, err = conn.Write(data)
		require.NoError(t, err)
		assert.Equal(t, [][]byte{data}, rc.writes)
	}
}

func TestPackets(t *testing.T) {
	config, err := ParseConfig("2-3", "3-7", "0")
	require.NoError(t, err)
	rc := &recordConn{}
	conn := NewConn(rc, config)

	data := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	for i := 0; i < 4; i++ {
		before := len(rc.writes)
		n, err := conn.Write(data)
		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		writes := rc.writes[before:]
		assert.Equal(t, data, bytes.Join(writes, nil))
		if i == 1 || i == 2 {
			assert.Greater(t, len(writes), 1)
			for _, w := range writes {
				assert.LessOrEqual(t, len(w), 7)
			}
		} else {
			assert.Len(t, writes, 1)
		}
	}
	assert.True(t, conn.WriterReplaceable())
}
