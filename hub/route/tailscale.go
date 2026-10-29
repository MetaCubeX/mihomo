package route

import (
	"context"
	"errors"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func getTailscaleExitNodes(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	provider, ok := proxy.Adapter().(C.TailscaleExitNodeProvider)
	if proxy.Type() != C.Tailscale || !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Tailscale outbound"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result, err := provider.TailscaleExitNodes(ctx)
	if errors.Is(err, C.ErrNotSupport) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Tailscale exit node discovery is not supported"))
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, ErrRequestTimeout)
		return
	}
	if err != nil {
		// LocalAPI errors may contain state paths or authentication details.
		render.Status(r, http.StatusBadGateway)
		render.JSON(w, r, newError("Tailscale exit node discovery failed"))
		return
	}
	render.JSON(w, r, result)
}
