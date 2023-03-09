package ngroklistener

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(TLS))
}

// ngrok TLS tunnel
// Note: only available for ngrok Enterprise user
type TLS struct {
	opts []config.TLSEndpointOption
}

// CaddyModule implements caddy.Module
func (*TLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.tls",
		New: func() caddy.Module {
			return new(TLS)
		},
	}
}

// Provision implements caddy.Provisioner
func (t *TLS) Provision(caddy.Context) error {
	return nil
}

// convert to ngrok's Tunnel type
func (t *TLS) NgrokTunnel() config.Tunnel {
	return config.TLSEndpoint(t.opts...)
}

func (t *TLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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

var _ caddy.Module = (*TLS)(nil)
var _ Tunnel = (*TLS)(nil)
var _ caddy.Provisioner = (*TLS)(nil)
var _ caddyfile.Unmarshaler = (*TLS)(nil)
