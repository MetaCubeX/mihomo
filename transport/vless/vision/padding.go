package vision

import (
	"bytes"
	"encoding/binary"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/randv2"
)

const (
	PaddingHeaderLen = uuid.Size + 1 + 2 + 2 // =21

	commandPaddingContinue byte = 0x00
	commandPaddingEnd      byte = 0x01
	commandPaddingDirect   byte = 0x02
)

func ApplyPadding(buffer *buf.Buffer, command byte, userUUID *[]byte, paddingTLS bool) {
	contentLen := int32(buffer.Len())
	var paddingLen int32
	if contentLen < 900 {
		if paddingTLS {
			//log.Debugln("long padding")
			paddingLen = randv2.Int32N(500) + 900 - contentLen
		} else {
			paddingLen = randv2.Int32N(256)
		}
	}

	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(paddingLen))
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(contentLen))
	buffer.ExtendHeader(1)[0] = command
	if userUUID != nil && *userUUID != nil {
		copy(buffer.ExtendHeader(uuid.Size), *userUUID)
		*userUUID = nil
	}

	buffer.Extend(int(paddingLen))
	log.Debugln("XTLS Vision write padding: command=%d, payloadLen=%d, paddingLen=%d", command, contentLen, paddingLen)
}

const xrayBufSize = 8192

func (vc *Conn) ReshapeBuffer(buffer *buf.Buffer) []*buf.Buffer {
	const bufferLimit = xrayBufSize - PaddingHeaderLen
	if buffer.Len() < bufferLimit {
		return []*buf.Buffer{buffer}
	}
	options := N.NewReadWaitOptions(nil, vc)
	var buffers []*buf.Buffer
	for buffer.Len() >= bufferLimit {
		cutAt := bytes.LastIndex(buffer.Bytes(), tlsApplicationDataStart)
		if cutAt < 21 || cutAt > bufferLimit {
			cutAt = xrayBufSize / 2
		}
		buffer2 := options.NewBuffer() // ensure the new buffer can send used in vc.WriteBuffer
		buf.Must(buf.Error(buffer2.ReadFullFrom(buffer, cutAt)))
		buffers = append(buffers, buffer2)
	}
	buffers = append(buffers, buffer)
	return buffers
}
