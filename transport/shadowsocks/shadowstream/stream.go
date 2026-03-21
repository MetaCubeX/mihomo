package shadowstream

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

const bufSize = 2048

type Writer struct {
	io.Writer
	cipher.Stream
	buf [bufSize]byte
}

// NewWriter wraps an io.Writer with stream cipher encryption.
func NewWriter(w io.Writer, s cipher.Stream) *Writer { return &Writer{Writer: w, Stream: s} }

func (w *Writer) Write(p []byte) (n int, err error) {
	buf := w.buf[:]
	for nw := 0; n < len(p) && err == nil; n += nw {
		end := n + len(buf)
		if end > len(p) {
			end = len(p)
		}
		w.XORKeyStream(buf, p[n:end])
		nw, err = w.Writer.Write(buf[:end-n])
	}
	return
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	buf := w.buf[:]
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		b := buf[:nr]
		w.XORKeyStream(b, b)
		if _, err = w.Writer.Write(b); err != nil {
			return
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			return
		}
	}
}

type Reader struct {
	io.Reader
	cipher.Stream
	buf [bufSize]byte
}

// NewReader wraps an io.Reader with stream cipher decryption.
func NewReader(r io.Reader, s cipher.Stream) *Reader { return &Reader{Reader: r, Stream: s} }

func (r *Reader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err != nil {
		return 0, err
	}
	r.XORKeyStream(p, p[:n])
	return
}

func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	buf := r.buf[:]
	for {
		nr, er := r.Reader.Read(buf)
		if nr > 0 {
			r.XORKeyStream(buf, buf[:nr])
			nw, ew := w.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				err = ew
				return
			}
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			return
		}
	}
}

// A Conn represents a Shadowsocks connection. It implements the net.Conn interface.
type Conn struct {
	net.Conn
	Cipher
	r       *Reader
	w       *Writer
	readIV  []byte
	writeIV []byte
}

// NewConn wraps a stream-oriented net.Conn with stream cipher encryption/decryption.
func NewConn(c net.Conn, ciph Cipher) *Conn { return &Conn{Conn: c, Cipher: ciph} }

func (c *Conn) initReader() error {
	if c.r == nil {
		iv, err := c.ObtainReadIV()
		if err != nil {
			return err
		}
		c.r = NewReader(c.Conn, c.Decrypter(iv))
	}
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *Conn) initWriter() error {
	if c.w == nil {
		iv, err := c.ObtainWriteIV()
		if err != nil {
			return err
		}
		if _, err := c.Conn.Write(iv); err != nil {
			return err
		}
		c.w = NewWriter(c.Conn, c.Encrypter(iv))
	}
	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

func (c *Conn) ObtainWriteIV() ([]byte, error) {
	if len(c.writeIV) == c.IVSize() {
		return c.writeIV, nil
	}

	iv := make([]byte, c.IVSize())

	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	c.writeIV = iv

	return iv, nil
}

func (c *Conn) ObtainReadIV() ([]byte, error) {
	if len(c.readIV) == c.IVSize() {
		return c.readIV, nil
	}

	iv := make([]byte, c.IVSize())

	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return nil, err
	}

	c.readIV = iv

	return iv, nil
}
