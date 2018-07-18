package hub

import (
	"fmt"
	"net/http"

	A "github.com/Dreamacro/clash/adapters"
	C "github.com/Dreamacro/clash/constant"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)
	r.Get("/{name}", getProxy)
	r.Put("/{name}", updateProxy)
	return r
}

type SampleProxy struct {
	Type string `json:"type"`
}

type Selector struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type URLTest struct {
	Type string `json:"type"`
	Now  string `json:"now"`
}

func transformProxy(proxy C.Proxy) interface{} {
	t := proxy.Type()
	switch t {
	case C.Selector:
		selector := proxy.(*A.Selector)
		return Selector{
			Type: t.String(),
			Now:  selector.Now(),
			All:  selector.All(),
		}
	case C.URLTest:
		return URLTest{
			Type: t.String(),
			Now:  proxy.(*A.URLTest).Now(),
		}
	default:
		return SampleProxy{
			Type: proxy.Type().String(),
		}
	}
}

type GetProxiesResponse struct {
	Proxies map[string]interface{} `json:"proxies"`
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	_, rawProxies := tunnel.Config()
	proxies := make(map[string]interface{})
	for name, proxy := range rawProxies {
		proxies[name] = transformProxy(proxy)
	}
	render.JSON(w, r, GetProxiesResponse{Proxies: proxies})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	_, proxies := tunnel.Config()
	proxy, exist := proxies[name]
	if !exist {
		w.WriteHeader(http.StatusNotFound)
		render.JSON(w, r, Error{
			Error: "Proxy not found",
		})
		return
	}
	render.JSON(w, r, transformProxy(proxy))
}

type UpdateProxyRequest struct {
	Name string `json:"name"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Format error",
		})
		return
	}

	name := chi.URLParam(r, "name")
	_, proxies := tunnel.Config()
	proxy, exist := proxies[name]
	if !exist {
		w.WriteHeader(http.StatusNotFound)
		render.JSON(w, r, Error{
			Error: "Proxy not found",
		})
		return
	}

	selector, ok := proxy.(*A.Selector)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Proxy can't update",
		})
		return
	}

	if err := selector.Set(req.Name); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: fmt.Sprintf("Selector update error: %s", err.Error()),
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
