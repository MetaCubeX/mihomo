package snellv6

import (
	"crypto/rand"
	"io"
	"time"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/internal/reuse"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	N "github.com/metacubex/sing/common/network"
)

func writeFirstRecord(conn io.Writer, mode Mode, psk []byte, profile *Profile, payload []byte) (reuse.RecordWriter, error) {
	switch mode {
	case ModeUnsafeRaw:
		writer := newRawWriter(conn)
		// Surge 6.7.0 (11520): FUN_1000154e0: chunks unsafe-raw payloads larger than the
		// 16-bit record payload field instead of truncating the length.
		if len(payload) > maxPayload {
			_, err := writer.Write(payload)
			if err != nil {
				return nil, err
			}
			return writer, nil
		}
		out := buf.NewSize(snell.HeaderPlainLen + len(payload))
		putHeader(out.Extend(snell.HeaderPlainLen), 0, len(payload))
		common.Must1(out.Write(payload))
		_, err := conn.Write(out.Bytes())
		out.Release()
		if err != nil {
			return nil, err
		}
		return writer, nil
	case ModeUnshaped:
		salt := make([]byte, snell.SaltLen)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			return nil, err
		}
		key := snell.DeriveKey(psk, salt)
		aead, err := snell.NewAEAD(key)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, snell.NonceLen)
		recordCount := 1
		if len(payload) > 0 {
			recordCount = (len(payload) + maxPayload - 1) / maxPayload
		}
		payloadCipherLen := len(payload)
		if len(payload) > 0 {
			payloadCipherLen += recordCount * snell.AEADTagLen
		}
		out := buf.NewSize(snell.SaltLen + recordCount*snell.HeaderCipherLen + payloadCipherLen)
		common.Must1(out.Write(salt))
		w := newUnshapedWriter(conn, aead, nonce)
		// Surge 6.7.0 (11520): FUN_10001596c: emits the salt once, then splits the first
		// unshaped payload into 0xffff-byte records.
		for remaining := payload; ; {
			recordLen := common.Min(len(remaining), maxPayload)
			w.sealHeader(out.Extend(snell.HeaderCipherLen), recordLen)
			if recordLen > 0 {
				aead.Seal(out.Extend(recordLen + snell.AEADTagLen)[:0], nonce, remaining[:recordLen], nil)
				snell.IncreaseNonce(nonce)
				remaining = remaining[recordLen:]
				if len(remaining) > 0 {
					continue
				}
			}
			break
		}
		_, err = conn.Write(out.Bytes())
		out.Release()
		if err != nil {
			return nil, err
		}
		return w, nil
	case ModeDefault:
		salt := make([]byte, snell.SaltLen)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			return nil, err
		}
		aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
		if err != nil {
			return nil, err
		}
		writer := newShapedWriter(conn, profile, salt, aead, make([]byte, snell.NonceLen))
		if len(payload) == 0 {
			writer.payloadLimitFor(time.Now())
			record := writer.makeSliceRecord(nil)
			_, err = conn.Write(record.Bytes())
			record.Release()
		} else {
			_, err = writer.Write(payload)
		}
		if err != nil {
			return nil, err
		}
		return writer, nil
	default:
		panic("snell: invalid v6 mode")
	}
}

func writeFirstRecordBuffer(conn io.Writer, mode Mode, psk []byte, profile *Profile, buffer *buf.Buffer) (reuse.RecordWriter, error) {
	switch mode {
	case ModeUnsafeRaw:
		writer := newRawWriter(conn)
		err := writer.WriteBuffer(buffer)
		if err != nil {
			return nil, err
		}
		return writer, nil
	case ModeUnshaped:
		if buffer.Len() > maxPayload {
			writer, err := writeFirstRecord(conn, mode, psk, profile, buffer.Bytes())
			buffer.Release()
			if err != nil {
				return nil, err
			}
			return writer, nil
		}
		salt := make([]byte, snell.SaltLen)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			buffer.Release()
			return nil, err
		}
		key := snell.DeriveKey(psk, salt)
		aead, err := snell.NewAEAD(key)
		if err != nil {
			buffer.Release()
			return nil, err
		}
		nonce := make([]byte, snell.NonceLen)
		record := buffer.ExtendHeader(snell.SaltLen + snell.HeaderCipherLen)
		copy(record[:snell.SaltLen], salt)
		writer := newUnshapedWriter(conn, aead, nonce)
		writer.sealHeader(record[snell.SaltLen:], buffer.Len()-(snell.SaltLen+snell.HeaderCipherLen))
		payloadCipher := buffer.From(snell.SaltLen + snell.HeaderCipherLen)
		buffer.Extend(snell.AEADTagLen)
		aead.Seal(payloadCipher[:0], nonce, payloadCipher, nil)
		snell.IncreaseNonce(nonce)
		_, err = conn.Write(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return nil, err
		}
		return writer, nil
	case ModeDefault:
		salt := make([]byte, snell.SaltLen)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			buffer.Release()
			return nil, err
		}
		aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
		if err != nil {
			buffer.Release()
			return nil, err
		}
		writer := newShapedWriter(conn, profile, salt, aead, make([]byte, snell.NonceLen))
		err = writer.WriteBuffer(buffer)
		if err != nil {
			return nil, err
		}
		return writer, nil
	default:
		panic("snell: invalid v6 mode")
	}
}

func readFirstRecord(conn io.Reader, mode Mode, psk []byte, profile *Profile, readWaitOptions N.ReadWaitOptions) (reuse.RecordReader, *buf.Buffer, error) {
	switch mode {
	case ModeUnsafeRaw:
		r := newRawReader(conn)
		r.InitializeReadWaiter(readWaitOptions)
		record, err := r.ReadRecord()
		if err != nil {
			return nil, nil, err
		}
		return r, record, nil
	case ModeUnshaped:
		salt := make([]byte, snell.SaltLen)
		_, err := io.ReadFull(conn, salt)
		if err != nil {
			return nil, nil, err
		}
		key := snell.DeriveKey(psk, salt)
		aead, err := snell.NewAEAD(key)
		if err != nil {
			return nil, nil, err
		}
		r := newUnshapedReader(conn, aead, make([]byte, snell.NonceLen))
		r.InitializeReadWaiter(readWaitOptions)
		record, err := r.ReadRecord()
		if err != nil {
			return nil, nil, err
		}
		return r, record, nil
	case ModeDefault:
		reader := newShapedReader(conn, psk, profile)
		reader.InitializeReadWaiter(readWaitOptions)
		record, err := reader.ReadRecord()
		if err != nil {
			return nil, nil, err
		}
		return reader, record, nil
	default:
		panic("snell: invalid v6 mode")
	}
}
