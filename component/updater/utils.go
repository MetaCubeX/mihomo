package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"

	"golang.org/x/exp/constraints"
)

const defaultHttpTimeout = time.Second * 90

func downloadForBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHttpTimeout)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func saveFile(bytes []byte, path string) error {
	return os.WriteFile(path, bytes, 0o644)
}

// LimitReachedError records the limit and the operation that caused it.
type LimitReachedError struct {
	Limit int64
}

// Error implements the [error] interface for *LimitReachedError.
//
// TODO(a.garipov): Think about error string format.
func (lre *LimitReachedError) Error() string {
	return fmt.Sprintf("attempted to read more than %d bytes", lre.Limit)
}

// limitedReader is a wrapper for [io.Reader] limiting the input and dealing
// with errors package.
type limitedReader struct {
	r     io.Reader
	limit int64
	n     int64
}

// Read implements the [io.Reader] interface.
func (lr *limitedReader) Read(p []byte) (n int, err error) {
	if lr.n == 0 {
		return 0, &LimitReachedError{
			Limit: lr.limit,
		}
	}

	p = p[:Min(lr.n, int64(len(p)))]

	n, err = lr.r.Read(p)
	lr.n -= int64(n)

	return n, err
}

// LimitReader wraps Reader to make it's Reader stop with ErrLimitReached after
// n bytes read.
func LimitReader(r io.Reader, n int64) (limited io.Reader, err error) {
	if n < 0 {
		return nil, &updateError{Message: "limit must be non-negative"}
	}

	return &limitedReader{
		r:     r,
		limit: n,
		n:     n,
	}, nil
}

// Min returns the smaller of x or y.
func Min[T constraints.Integer | ~string](x, y T) (res T) {
	if x < y {
		return x
	}

	return y
}
