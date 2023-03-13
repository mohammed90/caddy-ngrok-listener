package ngroklistener

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

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

	// Opaque, machine-readable metadata string for this session.
	//  Metadata is made available to you in the ngrok dashboard and the
	// Agents API resource. It is a useful way to allow you to uniquely identify
	// sessions. We suggest encoding the value in a structured format like JSON.
	Metadata string `json:"metadata,omitempty"`

	// Region configures the session to connect to a specific ngrok region.
	// If unspecified, ngrok will connect to the fastest region, which is usually what you want.
	// The [full list of ngrok regions] can be found in the ngrok documentation.
	Region string `json:"region,omitempty"`

	// Server configures the network address to dial to connect to the ngrok
	// service. Use this option only if you are connecting to a custom agent
	// ingress.
	//
	// See the [server_addr parameter in the ngrok docs] for additional details.
	Server string `json:"server,omitempty"`

	// HeartbeatTolerance configures the duration to wait for a response to a heartbeat
	// before assuming the session connection is dead and attempting to reconnect.
	//
	// See the [heartbeat_tolerance parameter in the ngrok docs] for additional details.
	HeartbeatTolerance time.Duration `json:"heartbeatTolerance,omitempty"`

	// HeartbeatInterval configures how often the session will send heartbeat
	// messages to the ngrok service to check session liveness.
	//
	// See the [heartbeat_interval parameter in the ngrok docs] for additional details.
	HeartbeatInterval time.Duration `json:"heartbeatInterval,omitempty"`

	tunnel Tunnel

	ctx context.Context
	l   *zap.Logger
}

// Provisions the ngrok listener wrapper
func (n *Ngrok) Provision(ctx caddy.Context) error {
	n.ctx = ctx
	n.l = ctx.Logger()

	if n.TunnelRaw == nil {
		n.TunnelRaw = json.RawMessage(`{"type": "tcp"}`)
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

	err = n.DoReplace()
	if err != nil {
		return fmt.Errorf("loading doing replacements: %v", err)
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

	if n.Metadata != "" {
		n.opts = append(n.opts, ngrok.WithMetadata(n.Metadata))
	}

	if n.Region != "" {
		n.opts = append(n.opts, ngrok.WithRegion(n.Region))
	}

	if n.Server != "" {
		n.opts = append(n.opts, ngrok.WithServer(n.Server))
	}

	if n.HeartbeatInterval != 0 {
		n.opts = append(n.opts, ngrok.WithHeartbeatInterval(n.HeartbeatInterval))
	}

	if n.HeartbeatTolerance != 0 {
		n.opts = append(n.opts, ngrok.WithHeartbeatTolerance(n.HeartbeatTolerance))
	}

	return nil
}

func (n *Ngrok) DoReplace() error {
	repl := caddy.NewReplacer()
	replaceableFields := []*string{
		&n.AuthToken,
		&n.Metadata,
		&n.Region,
		&n.Server,
	}

	for _, field := range replaceableFields {
		actual, err := repl.ReplaceOrErr(*field, false, true)
		if err != nil {
			return fmt.Errorf("error replacing fields: %v", err)
		}

		*field = actual
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

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			subdirective := d.Val()
			switch subdirective {
			case "authtoken":
				if !d.AllArgs(&n.AuthToken) {
					n.AuthToken = ""
				}
			case "metadata":
				if !d.AllArgs(&n.Metadata) {
					return d.ArgErr()
				}
			case "region":
				if !d.AllArgs(&n.Region) {
					return d.ArgErr()
				}
			case "server":
				if !d.AllArgs(&n.Server) {
					return d.ArgErr()
				}
			case "heartbeat_tolerance":
				if err := n.unmarshalHeartbeatTolerance(d); err != nil {
					return err
				}
			case "heartbeat_interval":
				if err := n.unmarshalHeartbeatInterval(d); err != nil {
					return err
				}
			case "tunnel":
				if err := n.unmarshalTunnel(d); err != nil {
					return err
				}
			default:
				return d.ArgErr()
			}
		}
	}

	return nil
}

func (n *Ngrok) unmarshalHeartbeatTolerance(d *caddyfile.Dispenser) error {
	var toleranceStr string
	if !d.AllArgs(&toleranceStr) {
		return d.ArgErr()
	}

	heartbeatTolerance, err := caddy.ParseDuration(toleranceStr)
	if err != nil {
		return d.Errf("parsing heartbeat_tolerance duration: %v", err)
	}

	n.HeartbeatTolerance = heartbeatTolerance

	return nil
}

func (n *Ngrok) unmarshalHeartbeatInterval(d *caddyfile.Dispenser) error {
	var intervalStr string
	if !d.AllArgs(&intervalStr) {
		return d.ArgErr()
	}

	heartbeatInterval, err := caddy.ParseDuration(intervalStr)
	if err != nil {
		return d.Errf("parsing heartbeat_interval duration: %v", err)
	}

	n.HeartbeatInterval = heartbeatInterval

	return nil
}

func (n *Ngrok) unmarshalTunnel(d *caddyfile.Dispenser) error {
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

	return nil
}

var (
	_ caddy.Module          = (*Ngrok)(nil)
	_ caddy.Provisioner     = (*Ngrok)(nil)
	_ caddy.Validator       = (*Ngrok)(nil)
	_ caddy.ListenerWrapper = (*Ngrok)(nil)
	_ caddyfile.Unmarshaler = (*Ngrok)(nil)
)
