package resource

import (
	"context"
	clashHttp "github.com/Dreamacro/clash/component/http"
	types "github.com/Dreamacro/clash/constant/provider"
	"io"
	"net/http"
	"os"
	"time"
)

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() types.VehicleType {
	return types.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Read() ([]byte, error) {
	return os.ReadFile(f.path)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url  string
	path string
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

func (h *HTTPVehicle) Type() types.VehicleType {
	return types.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Read() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	resp, err := clashHttp.HttpRequest(ctx, h.url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func NewHTTPVehicle(url string, path string) *HTTPVehicle {
	return &HTTPVehicle{url, path}
}
