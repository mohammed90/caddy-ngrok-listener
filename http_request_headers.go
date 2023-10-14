package ngroklistener

import (
	"github.com/caddyserver/caddy/v2"
	"golang.ngrok.com/ngrok/config"
)

type httpRequestHeaders struct {
	httpHeaders
}

func (h *httpRequestHeaders) Provision(caddy.Context) error {
	h.doReplace()

	for name, value := range h.Added {
		h.opts = append(h.opts, config.WithRequestHeader(name, value))
	}

	for _, name := range h.Removed {
		h.opts = append(h.opts, config.WithRemoveRequestHeader(name))
	}

	return nil
}
