package session

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/stretchr/testify/require"
)

func TestSessionSettingsWhileOpeningStreams(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	require.NoError(t, right.SetDeadline(time.Now().Add(5*time.Second)))
	var factory atomic.Pointer[padding.PaddingFactory]
	require.True(t, padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory))
	session := NewClientSession(discardConn{left}, &factory, "")
	defer session.Close()
	session.Run()
	var frames bytes.Buffer
	for _, item := range []struct {
		command byte
		data    []byte
	}{
		{cmdServerSettings, []byte("v=2")},
		{cmdHeartRequest, nil},
		{cmdSYNACK, nil},
	} {
		frames.WriteByte(item.command)
		_ = binary.Write(&frames, binary.BigEndian, uint32(1))
		_ = binary.Write(&frames, binary.BigEndian, uint16(len(item.data)))
		frames.Write(item.data)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 128; i++ {
			if _, err := right.Write(frames.Bytes()); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 128; i++ {
			stream, err := session.OpenStream()
			if err != nil {
				results <- err
				return
			}
			if err := stream.Close(); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}()
	close(start)
	wg.Wait()
	require.NoError(t, <-results)
	require.NoError(t, <-results)
}
