package ngroklistener

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(TCP))
}

// ngrok TCP tunnel
type TCP struct {
	opts []config.TCPEndpointOption

	// The remote TCP address to request for this edge
	RemoteAddr string `json:"remote_addr,omitempty"`

	// opaque metadata string for this tunnel.
	Metadata string `json:"metadata,omitempty"`

	// Rejects connections that do not match the given CIDRs
	AllowCIDR []string `json:"allow_cidr,omitempty"`

	// Rejects connections that match the given CIDRs and allows all other CIDRs.
	DenyCIDR []string `json:"deny_cidr,omitempty"`

	l *zap.Logger
}

// Provision implements caddy.Provisioner
func (t *TCP) Provision(ctx caddy.Context) error {
	t.l = ctx.Logger()

	if err := t.doReplace(); err != nil {
		return fmt.Errorf("loading doing replacements: %v", err)
	}

	if err := t.provisionOpts(); err != nil {
		return fmt.Errorf("provisioning tcp tunnel opts: %v", err)
	}

	return nil
}

func (t *TCP) provisionOpts() error {
	t.opts = append(t.opts, config.WithRemoteAddr(t.RemoteAddr))

	if t.Metadata != "" {
		t.opts = append(t.opts, config.WithMetadata(t.Metadata))
	}

	if t.AllowCIDR != nil {
		t.opts = append(t.opts, config.WithAllowCIDRString(t.AllowCIDR...))
	}

	if t.DenyCIDR != nil {
		t.opts = append(t.opts, config.WithDenyCIDRString(t.DenyCIDR...))
	}

	return nil
}

func (t *TCP) doReplace() error {
	repl := caddy.NewReplacer()
	replaceableFields := []*string{
		&t.Metadata,
	}

	for _, field := range replaceableFields {
		actual := repl.ReplaceKnown(*field, "")

		*field = actual
	}

	replacedAllowCIDR := make([]string, len(t.AllowCIDR))

	for index, cidr := range t.AllowCIDR {
		actual := repl.ReplaceKnown(cidr, "")

		replacedAllowCIDR[index] = actual
	}

	t.AllowCIDR = replacedAllowCIDR

	replacedDenyCIDR := make([]string, len(t.DenyCIDR))

	for index, cidr := range t.DenyCIDR {
		actual := repl.ReplaceKnown(cidr, "")

		replacedDenyCIDR[index] = actual
	}

	t.DenyCIDR = replacedDenyCIDR

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

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			subdirective := d.Val()
			switch subdirective {
			case "metadata":
				if !d.AllArgs(&t.Metadata) {
					return d.ArgErr()
				}
			case "remote_addr":
				if !d.AllArgs(&t.RemoteAddr) {
					return d.ArgErr()
				}
			case "allow":
				if d.CountRemainingArgs() == 0 {
					return d.ArgErr()
				}

				t.AllowCIDR = append(t.AllowCIDR, d.RemainingArgs()...)
			case "deny":
				if d.CountRemainingArgs() == 0 {
					return d.ArgErr()
				}

				t.DenyCIDR = append(t.DenyCIDR, d.RemainingArgs()...)
			default:
				return d.ArgErr()
			}
		}
	}

	return nil
}

var (
	_ caddy.Module          = (*TCP)(nil)
	_ Tunnel                = (*TCP)(nil)
	_ caddy.Provisioner     = (*TCP)(nil)
	_ caddyfile.Unmarshaler = (*TCP)(nil)
)
