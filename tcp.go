package ngroklistener

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(TCP))
}

// ngrok TCP tunnel
type TCP struct {
	// The TCP address to request for this edge
	Address string `json:"address,omitempty"`

	opts []config.TCPEndpointOption
}

// Provision implements caddy.Provisioner
func (t *TCP) Provision(caddy.Context) error {
	t.opts = append(t.opts, config.WithRemoteAddr(t.Address))
	return nil
}

// convert to ngrok's Tunnel type
func (t *TCP) NgrokTunnel() config.Tunnel {
	return config.TCPEndpoint(t.opts...)
}

// CaddyModule implements caddy.Module
func (*TCP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.tcp",
		New: func() caddy.Module {
			return new(TCP)
		},
	}
}

func (t *TCP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "address":
				t.Address = d.Val()
			default:
				return d.ArgErr()
			}
		}
	}
	return nil
}

var _ caddy.Module = (*TCP)(nil)
var _ Tunnel = (*TCP)(nil)
var _ caddy.Provisioner = (*TCP)(nil)
var _ caddyfile.Unmarshaler = (*TCP)(nil)
