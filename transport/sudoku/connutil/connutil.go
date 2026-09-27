package connutil

import "io"

type CloseReader interface{ CloseRead() error }
type CloseWriter interface{ CloseWrite() error }

func TryCloseRead(target any) error {
	if target == nil {
		return nil
	}
	if c, ok := target.(CloseReader); ok {
		return c.CloseRead()
	}
	return nil
}

func TryCloseWrite(target any) error {
	if target == nil {
		return nil
	}
	if c, ok := target.(CloseWriter); ok {
		return c.CloseWrite()
	}
	if c, ok := target.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func WriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func Copy(dst io.Writer, src io.Reader) (int64, error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(dst, src)
}
