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

func parse(packets, length, interval string) (*Config, error) {
	return ParseConfig(Options{Packets: packets, Length: length, Interval: interval})
}

func TestParseConfig(t *testing.T) {
	config, err := ParseConfig(Options{})
	require.NoError(t, err)
	assert.Equal(t, &Config{TLSHello: true, Lengths: []Range{{100, 200}}, Intervals: []Range{{10, 20}}}, config)

	config, err = parse("1-3", "5", "0")
	require.NoError(t, err)
	assert.Equal(t, &Config{PacketsFrom: 1, PacketsTo: 3, Lengths: []Range{{5, 5}}, Intervals: []Range{{0, 0}}}, config)

	// the lists take precedence over the single values
	config, err = ParseConfig(Options{Length: "5", Lengths: []string{"1", "2-3", "100-200"}, Intervals: []string{"0", "5-10"}, MaxSplit: "2-4"})
	require.NoError(t, err)
	assert.Equal(t, &Config{
		TLSHello:  true,
		Lengths:   []Range{{1, 1}, {2, 3}, {100, 200}},
		Intervals: []Range{{0, 0}, {5, 10}},
		MaxSplit:  Range{2, 4},
	}, config)

	for _, bad := range [][3]string{
		{"hello", "", ""}, {"0-3", "", ""}, {"3-1", "", ""},
		{"", "0", ""}, {"", "20-10", ""}, {"", "abc", ""},
		{"", "", "-1"}, {"", "", "1-x"}, {"", "", "999999"},
	} {
		_, err = parse(bad[0], bad[1], bad[2])
		assert.Error(t, err, "%v", bad)
	}
	for _, bad := range []Options{
		{Lengths: []string{"10", "0"}}, {Lengths: []string{"x"}},
		{Intervals: []string{"1", "-1"}},
		{MaxSplit: "x"}, {MaxSplit: "0-3"}, {MaxSplit: "-1"},
	} {
		_, err = ParseConfig(bad)
		assert.Error(t, err, "%v", bad)
	}
}

func TestTLSHello(t *testing.T) {
	for _, interval := range []string{"0", "0-1"} {
		config, err := parse("tlshello", "10-20", interval)
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
	config, err := parse("tlshello", "1", "0")
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
	config, err := parse("2-3", "3-7", "0")
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

// recordSizes returns the payload size of each TLS record in stream
func recordSizes(t *testing.T, stream []byte) (sizes []int) {
	for len(stream) > 0 {
		require.GreaterOrEqual(t, len(stream), 5)
		size := int(binary.BigEndian.Uint16(stream[3:5]))
		require.GreaterOrEqual(t, len(stream), 5+size)
		sizes = append(sizes, size)
		stream = stream[5+size:]
	}
	return
}

func TestLengthsAndMaxSplit(t *testing.T) {
	// tlshello: the sizes follow the list, the last entry repeats
	config, err := ParseConfig(Options{Lengths: []string{"1", "2", "40"}, Interval: "0"})
	require.NoError(t, err)
	rc := &recordConn{}
	hello := clientHello(100)
	_, err = NewConn(rc, config).Write(hello)
	require.NoError(t, err)
	require.Len(t, rc.writes, 1)
	assert.Equal(t, []int{1, 2, 40, 40, 17}, recordSizes(t, rc.writes[0]))
	payload, _ := reassemble(t, rc.writes[0], 40)
	assert.Equal(t, hello[5:], payload)

	// tlshello: max-split puts everything left in the last record
	config, err = ParseConfig(Options{Lengths: []string{"1", "2", "40"}, Interval: "0", MaxSplit: "3"})
	require.NoError(t, err)
	rc = &recordConn{}
	_, err = NewConn(rc, config).Write(hello)
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 97}, recordSizes(t, bytes.Join(rc.writes, nil)))

	// tlshello: a list of intervals sends every record on its own, even with zero delays
	config, err = ParseConfig(Options{Length: "30", Intervals: []string{"0", "1"}})
	require.NoError(t, err)
	rc = &recordConn{}
	_, err = NewConn(rc, config).Write(hello)
	require.NoError(t, err)
	assert.Len(t, rc.writes, 4)
	assert.Equal(t, []int{30, 30, 30, 10}, recordSizes(t, bytes.Join(rc.writes, nil)))

	// packets: same rules on plain writes
	config, err = ParseConfig(Options{Packets: "1", Lengths: []string{"3", "5"}, Interval: "0", MaxSplit: "4"})
	require.NoError(t, err)
	rc = &recordConn{}
	data := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	n, err := NewConn(rc, config).Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, [][]byte{data[:3], data[3:8], data[8:13], data[13:]}, rc.writes)
}
