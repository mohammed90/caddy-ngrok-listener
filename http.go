package ngroklistener

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(HTTP))
}

// ngrok HTTP tunnel
type HTTP struct {
	opts []config.HTTPEndpointOption
}

// CaddyModule implements caddy.Module
func (*HTTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http",
		New: func() caddy.Module {
			return new(HTTP)
		},
	}
}

// Provision implements caddy.Provisioner
func (*HTTP) Provision(caddy.Context) error {
	return nil
}

// convert to ngrok's Tunnel type
func (h *HTTP) NgrokTunnel() config.Tunnel {
	return config.HTTPEndpoint(h.opts...)
}

func (t *HTTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			default:
				return d.ArgErr()
			}
		}
	}
	return nil
}

var _ caddy.Module = (*HTTP)(nil)
var _ Tunnel = (*HTTP)(nil)
var _ caddy.Provisioner = (*HTTP)(nil)
var _ caddyfile.Unmarshaler = (*HTTP)(nil)
