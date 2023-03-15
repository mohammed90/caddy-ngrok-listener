package ngroklistener

import (
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(HTTP))
}

// ngrok HTTP tunnel
type HTTP struct {
	opts []config.HTTPEndpointOption

	// Rejects connections that do not match the given CIDRs
	AllowCIDR []string `json:"allow_cidr,omitempty"`

	// Rejects connections that match the given CIDRs and allows all other CIDRs.
	DenyCIDR []string `json:"deny_cidr,omitempty"`

	// the domain for this edge.
	Domain string `json:"domain,omitempty"`

	// opaque metadata string for this tunnel.
	Metadata string `json:"metadata,omitempty"`

	// sets the scheme for this edge.
	Scheme string `json:"scheme,omitempty"`

	// the 5XX response ratio at which the ngrok edge will stop sending requests to this tunnel.
	CircuitBreaker float64 `json:"circuit_breaker,omitempty"`

	// enables gzip compression.
	Compression bool `json:"compression,omitempty"`

	// enables the websocket-to-tcp converter.
	WebsocketTCPConverter bool `json:"websocket_tcp_converter,omitempty"`

	// A map of basicauth, username and password value pairs for this tunnel.
	BasicAuth []basicAuthCred `json:"basic_auth,omitempty"`

	OIDC *oidc `json:"oidc,omitempty"`

	l *zap.Logger
}

type basicAuthCred struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
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
func (t *HTTP) Provision(ctx caddy.Context) error {
	t.l = ctx.Logger()

	t.doReplace()

	if err := t.provisionOpts(ctx); err != nil {
		return fmt.Errorf("provisioning http tunnel opts: %v", err)
	}

	return nil
}

func (t *HTTP) provisionOpts(ctx caddy.Context) error {
	if t.Domain != "" {
		t.opts = append(t.opts, config.WithDomain(t.Domain))
	}

	if t.Metadata != "" {
		t.opts = append(t.opts, config.WithMetadata(t.Metadata))
	}

	if t.AllowCIDR != nil {
		t.opts = append(t.opts, config.WithAllowCIDRString(t.AllowCIDR...))
	}

	if t.DenyCIDR != nil {
		t.opts = append(t.opts, config.WithDenyCIDRString(t.DenyCIDR...))
	}

	if t.CircuitBreaker != 0 {
		t.opts = append(t.opts, config.WithCircuitBreaker(t.CircuitBreaker))
	}

	if t.Compression {
		t.opts = append(t.opts, config.WithCompression())
	}

	if t.Scheme != "" {
		switch t.Scheme {
		case "http":
			t.opts = append(t.opts, config.WithScheme(config.SchemeHTTP))
		case "https":
			t.opts = append(t.opts, config.WithScheme(config.SchemeHTTPS))
		default:
			return fmt.Errorf("unrecognized http tunnel scheme %s", t.Scheme)
		}
	}

	if t.WebsocketTCPConverter {
		t.opts = append(t.opts, config.WithWebsocketTCPConversion())
	}

	for _, basic_auth := range t.BasicAuth {
		t.opts = append(t.opts, config.WithBasicAuth(basic_auth.Username, basic_auth.Password))
	}

	if t.OIDC != nil {
		err := t.OIDC.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning oidc: %v", err)
		}
		t.opts = append(t.opts, t.OIDC.OIDCOption)
	}

	return nil
}

func (t *HTTP) doReplace() {
	repl := caddy.NewReplacer()
	replaceableFields := []*string{
		&t.Metadata,
		&t.Domain,
		&t.Scheme,
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

	for i, basic_auth := range t.BasicAuth {
		actualUsername := repl.ReplaceKnown(basic_auth.Username, "")

		actualPassword := repl.ReplaceKnown(basic_auth.Password, "")

		t.BasicAuth[i] = basicAuthCred{Username: actualUsername, Password: actualPassword}

	}

}

// convert to ngrok's Tunnel type
func (t *HTTP) NgrokTunnel() config.Tunnel {
	return config.HTTPEndpoint(t.opts...)
}

func (t *HTTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
			case "allow":
				if err := t.unmarshalAllowCidr(d); err != nil {
					return err
				}
			case "deny":
				if err := t.unmarshalDenyCidr(d); err != nil {
					return err
				}
			case "circuit_breaker":
				if err := t.unmarshalCircuitBreaker(d); err != nil {
					return err
				}
			case "compression":
				if err := t.unmarshalCompression(d); err != nil {
					return err
				}
			case "scheme":
				if !d.AllArgs(&t.Scheme) {
					return d.ArgErr()
				}
			case "websocket_tcp_converter":
				if err := t.unmarshalWebsocketTCPConverter(d); err != nil {
					return err
				}
			case "basic_auth":
				if err := t.unmarshalBasicAuth(d); err != nil {
					return err
				}
			case "oidc":
				if err := t.unmarshalOIDC(d); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective %s", subdirective)
			}
		}
	}

	return nil
}

func (t *HTTP) unmarshalWebsocketTCPConverter(d *caddyfile.Dispenser) error {
	var value string
	if !d.Args(&value) { // no arg default is true
		t.WebsocketTCPConverter = true
	} else if value == "off" {
		t.WebsocketTCPConverter = false
	} else { // arg was given check it
		var err error
		t.WebsocketTCPConverter, err = strconv.ParseBool(value)
		if err != nil {
			return d.Errf(`parsing websocket_tcp_converter value %+v: %w`, value, err)
		}
	}

	return nil
}

func (t *HTTP) unmarshalCompression(d *caddyfile.Dispenser) error {
	var value string
	if !d.Args(&value) { // no arg default is true
		t.Compression = true
	} else if value == "off" {
		t.Compression = false
	} else { // arg was given check it
		var err error
		t.Compression, err = strconv.ParseBool(value)
		if err != nil {
			return d.Errf(`parsing compression value %+v: %w`, value, err)
		}
	}

	return nil
}

func (t *HTTP) unmarshalAllowCidr(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	t.AllowCIDR = append(t.AllowCIDR, d.RemainingArgs()...)

	return nil
}

func (t *HTTP) unmarshalDenyCidr(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	t.DenyCIDR = append(t.DenyCIDR, d.RemainingArgs()...)

	return nil
}

func (t *HTTP) unmarshalBasicAuth(d *caddyfile.Dispenser) error {
	var (
		hasArgs        bool
		username       string
		password       string
		foundBasicAuth bool
	)

	minLenPassword := 8

	if d.NextArg() { // basic_auth is defined inline

		username = d.Val()

		hasArgs = true
		if !d.AllArgs(&password) {
			return d.ArgErr()
		}

		foundBasicAuth = true

		if len(password) < minLenPassword {
			return d.Err("password must be at least eight characters.")
		}

		t.BasicAuth = append(t.BasicAuth, basicAuthCred{Username: username, Password: password})

	}
	for nesting := d.Nesting(); d.NextBlock(nesting); { // block of basic_auth
		username := d.Val()

		if hasArgs {
			return d.Err("cannot specify basic_auth in both arguments and block") // because it would be weird
		}

		if !d.AllArgs(&password) {
			return d.ArgErr()
		}

		foundBasicAuth = true

		if len(password) < minLenPassword {
			return d.Err("password must be at least eight characters.")
		}

		t.BasicAuth = append(t.BasicAuth, basicAuthCred{Username: username, Password: password})
	}

	if !foundBasicAuth {
		return d.ArgErr()
	}

	return nil
}

func (t *HTTP) unmarshalCircuitBreaker(d *caddyfile.Dispenser) error {
	var ratio string
	if !d.AllArgs(&ratio) {
		return d.ArgErr()
	}

	circuitBreaker, err := strconv.ParseFloat(ratio, 64)
	if err != nil {
		return d.ArgErr()
	}

	t.CircuitBreaker = circuitBreaker

	return nil
}

func (t *HTTP) unmarshalOIDC(d *caddyfile.Dispenser) error {
	oidc := oidc{}
	err := oidc.UnmarshalCaddyfile(d)
	if err != nil {
		return d.Errf(`parsing oidc %w`, err)
	}

	t.OIDC = &oidc

	return nil
}

var (
	_ caddy.Module          = (*HTTP)(nil)
	_ Tunnel                = (*HTTP)(nil)
	_ caddy.Provisioner     = (*HTTP)(nil)
	_ caddyfile.Unmarshaler = (*HTTP)(nil)
)
