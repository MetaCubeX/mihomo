package vless

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func ReadAddons(data []byte) (*Addons, error) {
	reader := bytes.NewReader(data)
	var addons Addons
	for reader.Len() > 0 {
		tag, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, err
		}
		number, typ := int32(tag>>3), int8(tag&7)
		switch typ {
		case 0: // VARINT
			_, err = binary.ReadUvarint(reader)
			if err != nil {
				return nil, err
			}
		case 5: // I32
			var i32 [4]byte
			_, err = io.ReadFull(reader, i32[:])
			if err != nil {
				return nil, err
			}
		case 1: // I64
			var i64 [8]byte
			_, err = io.ReadFull(reader, i64[:])
			if err != nil {
				return nil, err
			}
		case 2: // LEN
			var bytesLen uint64
			bytesLen, err = binary.ReadUvarint(reader)
			if err != nil {
				return nil, err
			}
			bytesData := make([]byte, bytesLen)
			_, err = io.ReadFull(reader, bytesData)
			if err != nil {
				return nil, err
			}
			switch number {
			case 1:
				addons.Flow = string(bytesData)
			case 2:
				addons.Seed = bytesData
			}
		default: // group (3,4) has been deprecated we unneeded support
			return nil, fmt.Errorf("unknown protobuf message tag: %v", tag)
		}
	}
	return &addons, nil
}

func WriteAddons(addons *Addons) []byte {
	var writer bytes.Buffer
	if len(addons.Flow) > 0 {
		WriteUvarint(&writer, (1<<3)|2) // (field << 3) bit-or wire_type encoded as uint32 varint
		WriteUvarint(&writer, uint64(len(addons.Flow)))
		writer.WriteString(addons.Flow)
	}
	if len(addons.Seed) > 0 {
		WriteUvarint(&writer, (2<<3)|2) // (field << 3) bit-or wire_type encoded as uint32 varint
		WriteUvarint(&writer, uint64(len(addons.Seed)))
		writer.Write(addons.Seed)
	}
	return writer.Bytes()
}

func WriteUvarint(writer *bytes.Buffer, x uint64) {
	for x >= 0x80 {
		writer.WriteByte(byte(x) | 0x80)
		x >>= 7
	}
	writer.WriteByte(byte(x))
}
