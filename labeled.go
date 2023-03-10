package ngroklistener

import (
	"context"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(Labeled))
}

// ngrok Labeled Tunnel
type Labeled struct {
	ctx context.Context

	opts   []config.LabeledTunnelOption
	Labels map[string]string `json:"labels,omitempty"`

	l *zap.Logger
}

// CaddyModule implements caddy.Module
func (*Labeled) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.labeled",
		New: func() caddy.Module {
			return new(Labeled)
		},
	}
}

// Provision implements caddy.Provisioner
func (lt *Labeled) Provision(ctx caddy.Context) error {
	lt.ctx = ctx
	lt.l = ctx.Logger()

	for label, value := range lt.Labels {
		lt.opts = append(lt.opts, config.WithLabel(label, value))
		lt.l.Info("applying label", zap.String("label", label), zap.String("value", value))
	}

	return nil
}

// convert to ngrok's Tunnel type
func (lt *Labeled) NgrokTunnel() config.Tunnel {
	return config.LabeledTunnel(lt.opts...)
}

func (t *Labeled) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "labels":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					directive := d.Val()
					args := d.RemainingArgs()
					switch directive {
					case "label":
						if len(args) != 2 {
							return d.ArgErr()
						}
						if t.Labels == nil {
							t.Labels = map[string]string{}
						}
						t.Labels[args[0]] = args[1]
					default:
						return d.ArgErr()
					}
				}
			default:
				return d.ArgErr()

			}
		}
	}
	return nil
}

var (
	_ caddy.Module          = (*Labeled)(nil)
	_ Tunnel                = (*Labeled)(nil)
	_ caddy.Provisioner     = (*Labeled)(nil)
	_ caddyfile.Unmarshaler = (*Labeled)(nil)
)
