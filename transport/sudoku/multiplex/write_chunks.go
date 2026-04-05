package multiplex

import "io"

func writeAllChunks(w io.Writer, chunks ...[]byte) error {
	for _, chunk := range chunks {
		for len(chunk) > 0 {
			n, err := w.Write(chunk)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			chunk = chunk[n:]
		}
	}
	return nil
}
