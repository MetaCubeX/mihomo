package route

import "github.com/go-chi/chi/v5"

type externalRouter func(r chi.Router)

var externalRouters = make([]externalRouter, 0)

func Register(route ...externalRouter) {
	externalRouters = append(externalRouters, route...)
}

func addExternalRouters(r chi.Router) {
	if len(externalRouters) == 0 {
		return
	}

	for _, caller := range externalRouters {
		caller(r)
	}
}
