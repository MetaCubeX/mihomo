package resource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/http"
)

const (
	DefaultHttpTimeout = time.Second * 20

	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755

	execStderrLimit = 4096
)

var (
	etag = false
)

func ETag() bool {
	return etag
}

func SetETag(b bool) {
	etag = b
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return os.WriteFile(path, buf, fileMode)
}

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() P.VehicleType {
	return P.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Url() string {
	return "file://" + f.path
}

func (f *FileVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = os.ReadFile(f.path)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	return
}

func (f *FileVehicle) Proxy() string {
	return ""
}

func (f *FileVehicle) Write(buf []byte) error {
	return safeWrite(f.path, buf)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url       string
	path      string
	proxy     string
	header    http.Header
	timeout   time.Duration
	sizeLimit int64
	inRead    func(response *http.Response)
	provider  P.ProxyProvider
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

func (h *HTTPVehicle) Type() P.VehicleType {
	return P.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() string {
	return h.proxy
}

func (h *HTTPVehicle) Write(buf []byte) error {
	return safeWrite(h.path, buf)
}

func (h *HTTPVehicle) SetInRead(fn func(response *http.Response)) {
	h.inRead = fn
}

func (h *HTTPVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	header := h.header
	setIfNoneMatch := false
	if etag && oldHash.IsValid() {
		etagWithHash := cachefile.Cache().GetETagWithHash(h.url)
		if oldHash.Equal(etagWithHash.Hash) && etagWithHash.ETag != "" {
			if header == nil {
				header = http.Header{}
			} else {
				header = header.Clone()
			}
			header.Set("If-None-Match", etagWithHash.ETag)
			setIfNoneMatch = true
		}
	}
	resp, err := mihomoHttp.HttpRequest(ctx, h.url, http.MethodGet, header, nil, mihomoHttp.WithSpecialProxy(h.proxy))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if h.inRead != nil {
		h.inRead(resp)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if setIfNoneMatch && resp.StatusCode == http.StatusNotModified {
			return nil, oldHash, nil
		}
		err = errors.New(resp.Status)
		return
	}
	var reader io.Reader = resp.Body
	if h.sizeLimit > 0 {
		reader = io.LimitReader(reader, h.sizeLimit)
	}
	buf, err = io.ReadAll(reader)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	if etag {
		cachefile.Cache().SetETagWithHash(h.url, cachefile.EtagWithHash{
			Hash: hash,
			ETag: resp.Header.Get("ETag"),
			Time: time.Now(),
		})
	}
	return
}

func NewHTTPVehicle(url string, path string, proxy string, header http.Header, timeout time.Duration, sizeLimit int64) *HTTPVehicle {
	return &HTTPVehicle{
		url:       url,
		path:      path,
		proxy:     proxy,
		header:    header,
		timeout:   timeout,
		sizeLimit: sizeLimit,
	}
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int64
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	if lb.limit <= 0 {
		return lb.buf.Write(p)
	}

	remain := lb.limit - int64(lb.buf.Len())
	if remain > 0 {
		if int64(len(p)) > remain {
			_, _ = lb.buf.Write(p[:remain])
		} else {
			_, _ = lb.buf.Write(p)
		}
	}
	return len(p), nil
}

func (lb *limitedBuffer) Bytes() []byte {
	return lb.buf.Bytes()
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}

type ExecVehicle struct {
	command   []string
	path      string
	timeout   time.Duration
	sizeLimit int64
}

func (e *ExecVehicle) Type() P.VehicleType {
	return P.Exec
}

func (e *ExecVehicle) Path() string {
	return e.path
}

func (e *ExecVehicle) Url() string {
	if len(e.command) == 0 {
		return "exec://"
	}
	return "exec://" + filepath.Base(e.command[0])
}

func (e *ExecVehicle) Proxy() string {
	return ""
}

func (e *ExecVehicle) Write(buf []byte) error {
	return safeWrite(e.path, buf)
}

func (e *ExecVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	if len(e.command) == 0 {
		err = errors.New("exec provider command is empty")
		return
	}

	timeout := e.timeout
	if timeout <= 0 {
		timeout = DefaultHttpTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.command[0], e.command[1:]...)
	var stdout limitedBuffer
	stdout.limit = e.sizeLimit
	var stderr limitedBuffer
	stderr.limit = execStderrLimit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("exec provider command timed out: %w", ctx.Err())
			return
		}
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			err = fmt.Errorf("exec provider command failed: %w: %s", runErr, errMsg)
		} else {
			err = fmt.Errorf("exec provider command failed: %w", runErr)
		}
		return
	}

	buf = stdout.Bytes()
	hash = utils.MakeHash(buf)
	return
}

func NewExecVehicle(command []string, path string, timeout time.Duration, sizeLimit int64) *ExecVehicle {
	return &ExecVehicle{
		command:   append([]string(nil), command...),
		path:      path,
		timeout:   timeout,
		sizeLimit: sizeLimit,
	}
}
