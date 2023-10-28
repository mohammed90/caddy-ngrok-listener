package ngroklistener

import (
	"github.com/caddyserver/caddy/v2"
	"golang.ngrok.com/ngrok/config"
)

type httpResponseHeaders struct {
	httpHeaders
}

func (h *httpResponseHeaders) Provision(caddy.Context) error {
	h.doReplace()

	for name, value := range h.Added {
		h.opts = append(h.opts, config.WithResponseHeader(name, value))
	}

	for _, name := range h.Removed {
		h.opts = append(h.opts, config.WithRemoveResponseHeader(name))
	}

	return nil
}
