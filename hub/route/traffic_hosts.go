package route

import (
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"

	"github.com/metacubex/mihomo/tunnel/statistic"
)

const (
	trafficHostsDefaultTop = 50
	trafficHostsMaxTop     = 1000
)

func trafficHostsRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getTrafficHosts)
	r.Get("/check", getTrafficHostsCheck)
	return r
}

func getTrafficHosts(w http.ResponseWriter, r *http.Request) {
	stats := statistic.GetTrafficStats()
	if !stats.Enabled() {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("traffic statistics is disabled"))
		return
	}

	query := r.URL.Query()

	since, err := strconv.ParseInt(query.Get("since"), 10, 64)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid `since`"))
		return
	}
	until := time.Now().Unix()
	if raw := query.Get("until"); raw != "" {
		until, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid `until`"))
			return
		}
	}
	if since > until {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("`since` must not be greater than `until`"))
		return
	}

	match := strings.ToLower(query.Get("match"))
	suffixMatch := true
	switch match {
	case "", "suffix":
	case "exact":
		suffixMatch = false
	default:
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("`match` must be `suffix` or `exact`"))
		return
	}

	group := strings.ToLower(query.Get("group"))
	switch group {
	case "":
		group = "all"
	case "proxy", "direct", "all":
	default:
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("`group` must be `proxy`, `direct` or `all`"))
		return
	}

	top := trafficHostsDefaultTop
	if raw := query.Get("top"); raw != "" {
		top, err = strconv.Atoi(raw)
		if err != nil || top <= 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid `top`"))
			return
		}
		if top > trafficHostsMaxTop {
			top = trafficHostsMaxTop
		}
	}

	domain := strings.ToLower(strings.TrimSpace(query.Get("domain")))
	resp := stats.Query(since, until, domain, suffixMatch, group, top)
	render.JSON(w, r, resp)
}

func getTrafficHostsCheck(w http.ResponseWriter, r *http.Request) {
	stats := statistic.GetTrafficStats()
	if !stats.Enabled() {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("traffic statistics is disabled"))
		return
	}
	render.JSON(w, r, stats.Check())
}
