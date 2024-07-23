package route

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/go-chi/render"
)

func dohRouter() http.Handler {
	return http.HandlerFunc(dohHandler)
}

func dohHandler(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, "DNS section is disabled")
		return
	}

	var dnsData []byte
	var err error
	switch r.Method {
	case "GET":
		dnsData, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	case "POST":
		if r.Header.Get("Content-Type") != "application/dns-message" {
			render.Status(r, http.StatusInternalServerError)
			render.PlainText(w, r, "invalid content-type")
			return
		}
		reader := io.LimitReader(r.Body, 65535) // according to rfc8484, the maximum size of the DNS message is 65535 bytes
		dnsData, err = io.ReadAll(reader)
		_ = r.Body.Close()
	default:
		render.Status(r, http.StatusMethodNotAllowed)
		render.PlainText(w, r, "method not allowed")
		return
	}
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	dnsData, err = resolver.RelayDnsPacket(ctx, dnsData, dnsData)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dnsData)
}
