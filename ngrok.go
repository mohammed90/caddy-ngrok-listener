package ngroklistener

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(Ngrok))
}

type Tunnel interface {
	NgrokTunnel() config.Tunnel
}

// Ngrok is a `listener_wrapper` whose address is an ngrok-ingress address
type Ngrok struct {
	ctx context.Context

	// The user's ngrok authentication token
	AuthToken string `json:"auth_token,omitempty"`

	// The ngrok tunnel type and configuration; defaults to 'tcp'
	TunnelRaw json.RawMessage `json:"tunnel,omitempty" caddy:"namespace=caddy.listeners.ngrok.tunnels inline_key=type"`

	tunnel Tunnel

	l *zap.Logger
}

// Provisions the ngrok listener wrapper
func (n *Ngrok) Provision(ctx caddy.Context) error {
	n.ctx = ctx
	n.l = ctx.Logger()

	if n.TunnelRaw == nil {
		n.TunnelRaw = json.RawMessage(`{"tunnel": "tcp"}`)
	}
	tmod, err := ctx.LoadModule(n, "TunnelRaw")
	if err != nil {
		return fmt.Errorf("loading ngrok tunnel module: %v", err)
	}
	n.tunnel = tmod.(Tunnel)
	if n.tunnel == nil {
		return fmt.Errorf("tunnel is required")
	}

	if repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		n.AuthToken = repl.ReplaceKnown(n.AuthToken, "")
	}
	return nil
}

func (*Ngrok) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok",
		New: func() caddy.Module {
			return new(Ngrok)
		},
	}
}

// WrapListener return an ngrok listener instead the listener passed by Caddy
func (n *Ngrok) WrapListener(net.Listener) net.Listener {
	ln, err := ngrok.Listen(
		n.ctx,
		n.tunnel.NgrokTunnel(),
		ngrok.WithAuthtoken(n.AuthToken),
	)
	if err != nil {
		panic(err)
	}
	n.l.Info("ngrok listening", zap.String("address", ln.Addr().String()))
	return ln
}

func (n *Ngrok) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "auth_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n.AuthToken = d.Val()
			case "tunnel":
				var tunnelName string
				if !d.Args(&tunnelName) {
					tunnelName = "tcp"
				}
				unm, err := caddyfile.UnmarshalModule(d, "caddy.listeners.ngrok.tunnels."+tunnelName)
				if err != nil {
					return err
				}
				tun, ok := unm.(Tunnel)
				if !ok {
					return d.Errf("module %s is not an ngrok tunnel; is %T", tunnelName, unm)
				}
				n.TunnelRaw = caddyconfig.JSONModuleObject(tun, "type", tunnelName, nil)
			default:
				return d.ArgErr()
			}
		}
	}
	return nil
}

var _ caddy.Module = (*Ngrok)(nil)
var _ caddy.Provisioner = (*Ngrok)(nil)
var _ caddy.ListenerWrapper = (*Ngrok)(nil)
var _ caddyfile.Unmarshaler = (*Ngrok)(nil)
