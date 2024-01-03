package route

import (
	"net/http"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func cacheRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/fakeip/flush", flushFakeIPPool)
	return r
}

func flushFakeIPPool(w http.ResponseWriter, r *http.Request) {
	err := resolver.FlushFakeIP()
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}
