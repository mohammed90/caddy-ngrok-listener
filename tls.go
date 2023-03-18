package ngroklistener

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(TLS))
}

// ngrok TLS tunnel
// Note: only available for ngrok Enterprise user
type TLS struct {
	opts []config.TLSEndpointOption

	// the domain for this edge.
	Domain string `json:"domain,omitempty"`

	// opaque metadata string for this tunnel.
	Metadata string `json:"metadata,omitempty"`

	// Rejects connections that do not match the given CIDRs
	AllowCIDR []string `json:"allow_cidr,omitempty"`

	// Rejects connections that match the given CIDRs and allows all other CIDRs.
	DenyCIDR []string `json:"deny_cidr,omitempty"`

	// Path to the Cert.PEM for TLS termination
	CertPEM string `json:"cert,omitempty"`

	// Path to the Key.PEM for TLS termination
	KeyPEM string `json:"key,omitempty"`

	l *zap.Logger
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
func (t *TLS) Provision(ctx caddy.Context) error {
	t.l = ctx.Logger()

	t.doReplace()

	if err := t.provisionOpts(); err != nil {
		return fmt.Errorf("provisioning tls tunnel opts: %v", err)
	}

	return nil
}

func (t *TLS) provisionOpts() error {
	if strings.TrimSpace(t.Domain) != "" {
		t.opts = append(t.opts, config.WithDomain(t.Domain))
	}

	if strings.TrimSpace(t.Metadata) != "" {
		t.opts = append(t.opts, config.WithMetadata(t.Metadata))
	}

	if len(t.AllowCIDR) > 0 {
		t.opts = append(t.opts, config.WithAllowCIDRString(t.AllowCIDR...))
	}

	if len(t.DenyCIDR) > 0 {
		t.opts = append(t.opts, config.WithDenyCIDRString(t.DenyCIDR...))
	}

	if strings.TrimSpace(t.CertPEM) != "" && strings.TrimSpace(t.KeyPEM) == "" { // key not set
		return errors.New("provisioning tls termination - key is required when cert is set.")
	} else if strings.TrimSpace(t.CertPEM) == "" && strings.TrimSpace(t.KeyPEM) != "" { // cert not set
		return errors.New("provisioning tls_termination - - key is required when cert is set.")
	} else if strings.TrimSpace(t.CertPEM) != "" && strings.TrimSpace(t.KeyPEM) != "" { // both are set.
		certBytes, err := os.ReadFile(t.CertPEM)
		if err != nil {
			return fmt.Errorf("provisioning tls_termination - failed to read CertPem file: %v", err)
		}
		keyBytes, err := os.ReadFile(t.KeyPEM)
		if err != nil {
			return fmt.Errorf("provisioning tls_termination - failed to read KeyPem file: %v", err)
		}

		t.opts = append(t.opts, config.WithTLSTermination(config.WithTLSTerminationKeyPair(certBytes, keyBytes)))

	}

	return nil
}

func (t *TLS) doReplace() {
	repl := caddy.NewReplacer()
	replaceableFields := []*string{
		&t.Metadata,
		&t.Domain,
		&t.CertPEM,
		&t.KeyPEM,
	}

	for _, field := range replaceableFields {
		actual := repl.ReplaceKnown(*field, "")

		*field = actual
	}

	for index, cidr := range t.AllowCIDR {
		actual := repl.ReplaceKnown(cidr, "")

		t.AllowCIDR[index] = actual
	}

	for index, cidr := range t.DenyCIDR {
		actual := repl.ReplaceKnown(cidr, "")

		t.DenyCIDR[index] = actual
	}

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

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			subdirective := d.Val()
			switch subdirective {
			case "domain":
				if !d.AllArgs(&t.Domain) {
					return d.ArgErr()
				}
			case "metadata":
				if !d.AllArgs(&t.Metadata) {
					return d.ArgErr()
				}
			case "cert":
				if !d.AllArgs(&t.CertPEM) {
					return d.ArgErr()
				}
			case "key":
				if !d.AllArgs(&t.KeyPEM) {
					return d.ArgErr()
				}
			case "allow":
				if err := t.unmarshalAllowCidr(d); err != nil {
					return err
				}
			case "deny":
				if err := t.unmarshalDenyCidr(d); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective %s", subdirective)
			}
		}
	}

	return nil
}

func (t *TLS) unmarshalAllowCidr(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	t.AllowCIDR = append(t.AllowCIDR, d.RemainingArgs()...)

	return nil
}

func (t *TLS) unmarshalDenyCidr(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	t.DenyCIDR = append(t.DenyCIDR, d.RemainingArgs()...)

	return nil
}

var (
	_ caddy.Module          = (*TLS)(nil)
	_ Tunnel                = (*TLS)(nil)
	_ caddy.Provisioner     = (*TLS)(nil)
	_ caddyfile.Unmarshaler = (*TLS)(nil)
)
