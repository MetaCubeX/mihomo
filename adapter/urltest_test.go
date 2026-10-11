package adapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/stretchr/testify/assert"
)

func TestURLTestMethod(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method
	}))
	defer server.Close()

	proxy := adapter.NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := proxy.URLTest(ctx, server.URL, nil, "")
	assert.NoError(t, err)
	assert.Equal(t, http.MethodHead, got)

	_, err = proxy.URLTest(ctx, server.URL, nil, http.MethodGet)
	assert.NoError(t, err)
	assert.Equal(t, http.MethodGet, got)
}
