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
	ngrokZap "golang.ngrok.com/ngrok/log/zap"
)

func init() {
	caddy.RegisterModule(new(Ngrok))
}

type Tunnel interface {
	NgrokTunnel() config.Tunnel
}

// Ngrok is a `listener_wrapper` whose address is an ngrok-ingress address
type Ngrok struct {
	opts []ngrok.ConnectOption

	// The user's ngrok authentication token
	AuthToken string `json:"authtoken,omitempty"`

	// The ngrok tunnel type and configuration; defaults to 'tcp'
	TunnelRaw json.RawMessage `json:"tunnel,omitempty" caddy:"namespace=caddy.listeners.ngrok.tunnels inline_key=type"`

	tunnel Tunnel

	ctx context.Context
	l   *zap.Logger
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

	var ok bool
	n.tunnel, ok = tmod.(Tunnel)

	if !ok {
		return fmt.Errorf("loading ngrok tunnel module: %v", err)
	}

	if repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		n.AuthToken = repl.ReplaceKnown(n.AuthToken, "")
	}
	return nil
}

func (n *Ngrok) ProvisionOpts() error {
	n.opts = append(n.opts, ngrok.WithLogger(ngrokZap.NewLogger(n.l)))

	if n.AuthToken == "" {
		n.opts = append(n.opts, ngrok.WithAuthtokenFromEnv())
	} else {
		n.opts = append(n.opts, ngrok.WithAuthtoken(n.AuthToken))
	}


	return nil
}

// Validate implements caddy.Validator.
func (n *Ngrok) Validate() error {
	if n.tunnel == nil {
		return fmt.Errorf("tunnel is required")
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
	if err := n.ProvisionOpts(); err != nil {
		panic(err)
	}

	ln, err := ngrok.Listen(
		n.ctx,
		n.tunnel.NgrokTunnel(),
		n.opts...,
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

var (
	_ caddy.Module          = (*Ngrok)(nil)
	_ caddy.Provisioner     = (*Ngrok)(nil)
	_ caddy.Validator       = (*Ngrok)(nil)
	_ caddy.ListenerWrapper = (*Ngrok)(nil)
	_ caddyfile.Unmarshaler = (*Ngrok)(nil)
)
