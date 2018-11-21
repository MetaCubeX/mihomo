package route

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	A "github.com/Dreamacro/clash/adapters/outbound"
	C "github.com/Dreamacro/clash/constant"
	T "github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getProxy)
		r.Get("/delay", getProxyDelay)
		r.Put("/", updateProxy)
	})
	return r
}

// When name is composed of a partial escape string, Golang does not unescape it
func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if newName, err := url.PathUnescape(name); err == nil {
			name = newName
		}
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		proxies := T.Instance().Proxies()
		proxy, exist := proxies[name]
		if !exist {
			w.WriteHeader(http.StatusNotFound)
			render.Respond(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	proxies := T.Instance().Proxies()
	render.Respond(w, r, map[string]map[string]C.Proxy{
		"proxies": proxies,
	})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	render.Respond(w, r, proxy)
}

type UpdateProxyRequest struct {
	Name string `json:"name"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	selector, ok := proxy.(*A.Selector)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, ErrBadRequest)
		return
	}

	if err := selector.Set(req.Name); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, newError(fmt.Sprintf("Selector update error: %s", err.Error())))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getProxyDelay(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	url := query.Get("url")
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Respond(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	sigCh := make(chan int16)
	go func() {
		t, err := A.DelayTest(proxy, url)
		if err != nil {
			sigCh <- 0
		}
		sigCh <- t
	}()

	select {
	case <-time.After(time.Millisecond * time.Duration(timeout)):
		w.WriteHeader(http.StatusRequestTimeout)
		render.Respond(w, r, ErrRequestTimeout)
	case t := <-sigCh:
		if t == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			render.Respond(w, r, newError("An error occurred in the delay test"))
		} else {
			render.Respond(w, r, map[string]int16{
				"delay": t,
			})
		}
	}
}
