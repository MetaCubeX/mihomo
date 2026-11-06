package route

import (
	"context"
	"math"
	"net/url"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	MD "github.com/metacubex/mihomo/dns"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/miekg/dns"
	"github.com/samber/lo"
)

func dnsRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/query", queryDNS)
	r.Get("/policy/match", matchDNSPolicy)
	return r
}

type dnsPolicyMatcher interface {
	MatchPolicy(domain string, qtype uint16) MD.PolicyMatch
}

func matchDNSPolicy(w http.ResponseWriter, r *http.Request) {
	loaded := resolver.DefaultResolver
	if loaded == nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}

	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	domain := query.Get("domain")
	if _, valid := dns.IsDomainName(dns.Fqdn(domain)); !valid || domain == "" || domain == "." ||
		strings.ContainsAny(domain, " \t\r\n/\\:?#*@+") {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid query domain"))
		return
	}
	qTypeStr, _ := lo.Coalesce(query.Get("type"), "A")
	qType, valid := dns.StringToType[strings.ToUpper(qTypeStr)]
	if !valid {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid query type"))
		return
	}
	matcher, ok := loaded.(dnsPolicyMatcher)
	if !ok {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS policy matching is unavailable"))
		return
	}
	render.JSON(w, r, matcher.MatchPolicy(domain, qType))
}

func queryDNS(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}

	name := r.URL.Query().Get("name")
	qTypeStr, _ := lo.Coalesce(r.URL.Query().Get("type"), "A")

	qType, exist := dns.StringToType[qTypeStr]
	if !exist {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid query type"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), qType)
	resp, err := resolver.DefaultResolver.ExchangeContext(ctx, &msg)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	responseData := render.M{
		"Status":   resp.Rcode,
		"Question": resp.Question,
		"TC":       resp.Truncated,
		"RD":       resp.RecursionDesired,
		"RA":       resp.RecursionAvailable,
		"AD":       resp.AuthenticatedData,
		"CD":       resp.CheckingDisabled,
	}

	rr2Json := func(rr dns.RR, _ int) render.M {
		header := rr.Header()
		return render.M{
			"name": header.Name,
			"type": header.Rrtype,
			"TTL":  header.Ttl,
			"data": lo.Substring(rr.String(), len(header.String()), math.MaxUint),
		}
	}

	if len(resp.Answer) > 0 {
		responseData["Answer"] = lo.Map(resp.Answer, rr2Json)
	}
	if len(resp.Ns) > 0 {
		responseData["Authority"] = lo.Map(resp.Ns, rr2Json)
	}
	if len(resp.Extra) > 0 {
		responseData["Additional"] = lo.Map(resp.Extra, rr2Json)
	}

	render.JSON(w, r, responseData)
}
