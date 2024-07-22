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
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}

	if r.Header.Get("Accept") != "application/dns-message" {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("invalid accept header"))
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
			render.JSON(w, r, newError("invalid content-type"))
			return
		}
		dnsData, err = io.ReadAll(r.Body)
		_ = r.Body.Close()
	default:
		render.Status(r, http.StatusMethodNotAllowed)
		render.JSON(w, r, newError("method not allowed"))
		return
	}
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	dnsData, err = resolver.RelayDnsPacket(ctx, dnsData, dnsData)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.Status(r, http.StatusOK)
	render.Data(w, r, dnsData)
}
