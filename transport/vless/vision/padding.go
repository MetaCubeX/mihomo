package vision

import (
	"bytes"
	"encoding/binary"

	"github.com/metacubex/mihomo/common/buf"
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

func WriteWithPadding(buffer *buf.Buffer, p []byte, command byte, userUUID *uuid.UUID, paddingTLS bool) {
	contentLen := int32(len(p))
	var paddingLen int32
	if contentLen < 900 {
		if paddingTLS {
			//log.Debugln("long padding")
			paddingLen = randv2.Int32N(500) + 900 - contentLen
		} else {
			paddingLen = randv2.Int32N(256)
		}
	}
	if userUUID != nil {
		buffer.Write(userUUID.Bytes())
	}

	buffer.WriteByte(command)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(contentLen))
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(paddingLen))
	buffer.Write(p)

	buffer.Extend(int(paddingLen))
	log.Debugln("XTLS Vision write padding1: command=%v, payloadLen=%v, paddingLen=%v", command, contentLen, paddingLen)
}

func ApplyPadding(buffer *buf.Buffer, command byte, userUUID *uuid.UUID, paddingTLS bool) {
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
	if userUUID != nil {
		copy(buffer.ExtendHeader(uuid.Size), userUUID.Bytes())
	}

	buffer.Extend(int(paddingLen))
	log.Debugln("XTLS Vision write padding2: command=%d, payloadLen=%d, paddingLen=%d", command, contentLen, paddingLen)
}

func ReshapeBuffer(buffer *buf.Buffer) *buf.Buffer {
	if buffer.Len() <= buf.BufferSize-PaddingHeaderLen {
		return nil
	}
	cutAt := bytes.LastIndex(buffer.Bytes(), tlsApplicationDataStart)
	if cutAt == -1 {
		cutAt = buf.BufferSize / 2
	}
	buffer2 := buf.New()
	buffer2.Write(buffer.From(cutAt))
	buffer.Truncate(cutAt)
	return buffer2
}
