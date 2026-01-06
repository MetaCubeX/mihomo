package multiplex

import (
	"fmt"
	"io"
)

const (
	// MagicByte marks a Sudoku tunnel connection that will switch into multiplex mode.
	// It is sent after the Sudoku handshake + downlink mode byte.
	//
	// Keep it distinct from UoTMagicByte and address type bytes.
	MagicByte byte = 0xED
	Version   byte = 0x01
)

func WritePreface(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("nil writer")
	}
	_, err := w.Write([]byte{MagicByte, Version})
	return err
}

func ReadVersion(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func ValidateVersion(v byte) error {
	if v != Version {
		return fmt.Errorf("unsupported multiplex version: %d", v)
	}
	return nil
}

