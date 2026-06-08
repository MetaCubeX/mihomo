package bundle

import (
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sevenzip"
)

func MakeBundleFile(path string) resource.BundleFile {
	if path == "" {
		return nil
	}
	return func() (fs.File, error) {
		return Open(path)
	}
}

func Open(path string) (fs.File, error) {
	r, err := sevenzip.OpenReader(C.Path.BundleMRS())
	if err != nil {
		return nil, fmt.Errorf("open bundle file error: %w", err)
	}
	f, err := r.Open(path)
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("open path in bundle file error: %w", err)
	}
	return file{f, r}, nil
}

type file struct {
	fs.File
	closer io.Closer
}

func (f file) Close() error {
	err1 := f.File.Close()
	err2 := f.closer.Close()
	return errors.Join(err1, err2)
}
