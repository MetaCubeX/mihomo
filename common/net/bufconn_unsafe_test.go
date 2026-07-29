package net

import (
	"bufio"
	"bytes"
	"io"
	stdnet "net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufioReaderLayout(t *testing.T) {
	standard := reflect.TypeOf(bufio.Reader{})
	mirror := reflect.TypeOf(bufioReader{})

	require.Equal(t, standard.Size(), mirror.Size())
	require.Equal(t, standard.Align(), mirror.Align())
	require.Equal(t, standard.NumField(), mirror.NumField())

	for i := 0; i < standard.NumField(); i++ {
		standardField := standard.Field(i)
		mirrorField := mirror.Field(i)
		assert.Equal(t, standardField.Name, mirrorField.Name)
		assert.Equal(t, standardField.Type, mirrorField.Type)
		assert.Equal(t, standardField.Offset, mirrorField.Offset)
		assert.Equal(t, standardField.Anonymous, mirrorField.Anonymous)
	}
}

type testReaderConn struct {
	stdnet.Conn
	*bytes.Reader
}

func (c *testReaderConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func TestBufferedConnGrow(t *testing.T) {
	data := make([]byte, 32*1024)
	for i := range data {
		data[i] = byte(i)
	}

	conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(data)})
	reader := conn.Reader()

	first, err := conn.Peek(1)
	require.NoError(t, err)
	require.Equal(t, data[:1], first)
	require.Less(t, conn.Buffered(), len(data))

	conn.Grow(len(data))
	peeked, err := conn.Peek(len(data))
	require.NoError(t, err)
	assert.Equal(t, data, peeked)
	assert.Same(t, reader, conn.Reader())
	assert.Equal(t, 32*1024, conn.Reader().Size())

	_, err = conn.Peek(32*1024 + 1)
	assert.ErrorIs(t, err, bufio.ErrBufferFull)
	assert.Equal(t, 32*1024, conn.Reader().Size())

	read := make([]byte, len(data))
	_, err = io.ReadFull(conn, read)
	require.NoError(t, err)
	assert.Equal(t, data, read)

	conn = NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(data)})
	initialSize := conn.Reader().Size()
	peeked, err = conn.Peek(32*1024 + 1)
	assert.ErrorIs(t, err, bufio.ErrBufferFull)
	assert.Equal(t, data[:initialSize], peeked)
	assert.Equal(t, initialSize, conn.Reader().Size())
}

func TestBufferedConnAppendData(t *testing.T) {
	t.Run("prepends to unread underlying data", func(t *testing.T) {
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader([]byte("underlying"))})
		require.True(t, conn.AppendData([]byte("appended")))

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, []byte("appendedunderlying"), data)
	})

	t.Run("slides buffered data to make room", func(t *testing.T) {
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(bytes.Repeat([]byte("a"), 4096))})
		_, err := conn.Peek(4096)
		require.NoError(t, err)
		_, err = conn.Discard(2048)
		require.NoError(t, err)
		require.True(t, conn.AppendData(bytes.Repeat([]byte("b"), 2048)))

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(bytes.Repeat([]byte("a"), 2048), bytes.Repeat([]byte("b"), 2048)...), data)
	})

	t.Run("grows to make room", func(t *testing.T) {
		original := bytes.Repeat([]byte("a"), 4096)
		appended := bytes.Repeat([]byte("b"), 2048)
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(original)})
		_, err := conn.Peek(4096)
		require.NoError(t, err)
		_, err = conn.Discard(1024)
		require.NoError(t, err)
		require.True(t, conn.AppendData(appended))
		assert.Equal(t, 8192, conn.Reader().Size())

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(original[1024:], appended...), data)
	})

	t.Run("grows beyond 32 KiB", func(t *testing.T) {
		original := bytes.Repeat([]byte("a"), 32*1024)
		appended := bytes.Repeat([]byte("b"), 1025)
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(original)})
		conn.Grow(len(original))
		_, err := conn.Peek(32 * 1024)
		require.NoError(t, err)
		_, err = conn.Discard(1024)
		require.NoError(t, err)
		require.True(t, conn.AppendData(appended))
		assert.Greater(t, conn.Reader().Size(), 32*1024)

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(original[1024:], appended...), data)
	})

	t.Run("appends after explicit growth", func(t *testing.T) {
		original := bytes.Repeat([]byte("a"), 5000)
		appended := bytes.Repeat([]byte("b"), 1000)
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(original)})
		conn.Grow(len(original))
		_, err := conn.Peek(len(original))
		require.NoError(t, err)
		require.True(t, conn.AppendData(appended))

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(original, appended...), data)
	})
}

func TestBufferedConnPrependData(t *testing.T) {
	t.Run("before unbuffered data", func(t *testing.T) {
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader([]byte("underlying"))})
		conn.PrependData([]byte("prepended"))

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, []byte("prependedunderlying"), data)
	})

	t.Run("uses consumed headroom", func(t *testing.T) {
		original := bytes.Repeat([]byte("a"), 4096)
		prepended := bytes.Repeat([]byte("b"), 1024)
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(original)})
		_, err := conn.Peek(len(original))
		require.NoError(t, err)
		_, err = conn.Discard(2048)
		require.NoError(t, err)
		conn.PrependData(prepended)
		assert.Equal(t, 4096, conn.Reader().Size())

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(prepended, original[2048:]...), data)
	})

	t.Run("shifts buffered data", func(t *testing.T) {
		original := bytes.Repeat([]byte("a"), 2048)
		prepended := bytes.Repeat([]byte("b"), 1024)
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(original)})
		_, err := conn.Peek(len(original))
		require.NoError(t, err)
		conn.PrependData(prepended)
		assert.Equal(t, 4096, conn.Reader().Size())

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(prepended, original...), data)
	})

	t.Run("grows to make room", func(t *testing.T) {
		original := bytes.Repeat([]byte("a"), 4096)
		prepended := bytes.Repeat([]byte("b"), 2048)
		conn := NewBufferedConn(&testReaderConn{Reader: bytes.NewReader(original)})
		_, err := conn.Peek(len(original))
		require.NoError(t, err)
		conn.PrependData(prepended)
		assert.Equal(t, 8192, conn.Reader().Size())

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		assert.Equal(t, append(prepended, original...), data)
	})
}
