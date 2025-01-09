package route

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

func groupRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getGroups)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getGroup)
		r.Get("/delay", getGroupDelay)
	})
	return r
}

func getGroups(w http.ResponseWriter, r *http.Request) {
	var gs []C.Proxy
	for _, p := range tunnel.Proxies() {
		if _, ok := p.Adapter().(C.Group); ok {
			gs = append(gs, p)
		}
	}
	render.JSON(w, r, render.M{
		"proxies": gs,
	})
}

func getGroup(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if _, ok := proxy.Adapter().(C.Group); ok {
		render.JSON(w, r, proxy)
		return
	}
	render.Status(r, http.StatusNotFound)
	render.JSON(w, r, ErrNotFound)
}

func getGroupDelay(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	group, ok := proxy.Adapter().(C.Group)
	if !ok {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}

	if selectAble, ok := proxy.Adapter().(outboundgroup.SelectAble); ok && proxy.Type() != C.Selector {
		selectAble.ForceSet("")
		cachefile.Cache().SetSelected(proxy.Name(), "")
	}

	query := r.URL.Query()
	url := query.Get("url")
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 32)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](query.Get("expected"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Millisecond*time.Duration(timeout))
	defer cancel()

	dm, err := group.URLTest(ctx, url, expectedStatus)
	if err != nil {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.JSON(w, r, dm)
}
