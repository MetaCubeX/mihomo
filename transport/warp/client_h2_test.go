package warp

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/metacubex/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestWARPHTTP2DatagramHasNoStandardContextID(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	stream := &h2DatagramStream{requestBody: requestWriter}
	payload := []byte{0x45, 0, 0, 20}
	errCh := make(chan error, 1)
	go func() { errCh <- stream.SendDatagram(payload) }()

	reader := quicvarint.NewReader(requestReader)
	capsuleType, err := quicvarint.Read(reader)
	require.NoError(t, err)
	require.Equal(t, h2DatagramCapsuleType, capsuleType)
	payloadLength, err := quicvarint.Read(reader)
	require.NoError(t, err)
	require.Equal(t, uint64(len(payload)), payloadLength)
	got := make([]byte, payloadLength)
	_, err = io.ReadFull(reader, got)
	require.NoError(t, err)
	require.Equal(t, payload, got, "WARP H2 carries raw IP; standard CONNECT-IP would prepend Context ID 0")
	require.NoError(t, <-errCh)
	_ = requestReader.Close()
	_ = requestWriter.Close()
}

func TestWARPHTTP2CapsuleSizeLimit(t *testing.T) {
	frame := quicvarint.Append(nil, h2DatagramCapsuleType)
	frame = quicvarint.Append(frame, maxH2CapsulePayload+1)
	stream := &h2DatagramStream{responseBody: io.NopCloser(bytes.NewReader(frame))}
	_, err := stream.ReceiveDatagram()
	require.ErrorContains(t, err, "size limit")
}

func TestWARPDecrementsIPv4TTLAndUpdatesChecksum(t *testing.T) {
	packet := make([]byte, ipv4HeaderLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], ipv4HeaderLen)
	packet[8] = 2
	packet[9] = 6
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet))

	require.NoError(t, decrementHopLimit(packet))
	require.Equal(t, byte(1), packet[8])
	checksum := binary.BigEndian.Uint16(packet[10:12])
	require.NotZero(t, checksum)
	require.Equal(t, checksum, ipv4Checksum(packet))
	require.Error(t, decrementHopLimit(packet))
}

func TestWARPDecrementsIPv4TTLWithOptions(t *testing.T) {
	packet := make([]byte, 24)
	packet[0] = 0x46
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{198, 51, 100, 1})
	copy(packet[20:24], []byte{1, 1, 0, 0})
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet))

	require.NoError(t, decrementHopLimit(packet))
	require.Equal(t, byte(63), packet[8])
	require.Equal(t, binary.BigEndian.Uint16(packet[10:12]), ipv4Checksum(packet))
}

func TestWARPRejectsInvalidIPv4HeaderLength(t *testing.T) {
	packet := make([]byte, ipv4HeaderLen)
	packet[0] = 0x44
	require.ErrorContains(t, validateIPPacket(packet), "header length")

	packet[0] = 0x46
	require.ErrorContains(t, validateIPPacket(packet), "exceeds packet length")
}
