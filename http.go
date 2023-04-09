package ngroklistener

import (
	"bytes"
	"encoding/json"
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

	// A map of basicauth, username and password value pairs for this tunnel.
	BasicAuth []basicAuthCred `json:"basic_auth,omitempty"`

	// key-value of the HTTP tunnel options to be enabled and configured
	Options caddy.ModuleMap `json:"options" caddy:"namespace=caddy.listeners.ngrok.tunnels.http.options"`

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

	mods, err := ctx.LoadModule(t, "Options")
	if err != nil {
		return err
	}
	for _, v := range mods.(map[string]any) {
		if m, ok := v.(HTTPOptioner); ok && m.HTTPOption() != nil {
			t.opts = append(t.opts, m.HTTPOption())
		}
	}

	if err := t.provisionOpts(); err != nil {
		return fmt.Errorf("provisioning http tunnel opts: %v", err)
	}

	return nil
}

func (t *HTTP) provisionOpts() error {
	for _, basic_auth := range t.BasicAuth {
		t.opts = append(t.opts, config.WithBasicAuth(basic_auth.Username, basic_auth.Password))
	}

	return nil
}

func (t *HTTP) doReplace() {
	repl := caddy.NewReplacer()

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
	if t.Options == nil {
		t.Options = make(caddy.ModuleMap)
	}
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			subdirective := d.Val()
			var val string
			switch subdirective {
			case "domain":
				if !d.AllArgs(&val) {
					return d.ArgErr()
				}
				t.Options["domain"] = json.RawMessage(quoteString(val))
			case "metadata":
				if !d.AllArgs(&val) {
					return d.ArgErr()
				}
				t.Options["metadata"] = json.RawMessage(quoteString(val))
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
				if !d.AllArgs(&val) {
					return d.ArgErr()
				}
				t.Options["scheme"] = json.RawMessage(quoteString(val))
			case "websocket_tcp_converter":
				if err := t.unmarshalWebsocketTCPConverter(d); err != nil {
					return err
				}
			case "basic_auth":
				if err := t.unmarshalBasicAuth(d); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective: %s", subdirective)
			}
		}
	}

	return nil
}

func (t *HTTP) unmarshalWebsocketTCPConverter(d *caddyfile.Dispenser) error {
	var value string
	if !d.Args(&value) { // no arg default is true
		t.Options["websocket_tcp_conversion"] = json.RawMessage("true")
	} else if value == "off" {
		t.Options["websocket_tcp_conversion"] = json.RawMessage("false")
	} else { // arg was given check it
		var err error
		_, err = strconv.ParseBool(value)
		if err != nil {
			return d.Errf(`parsing websocket_tcp_converter value %+v: %w`, value, err)
		}
		t.Options["websocket_tcp_conversion"] = json.RawMessage(value)
	}

	return nil
}

func (t *HTTP) unmarshalCompression(d *caddyfile.Dispenser) error {
	var value string
	if !d.Args(&value) { // no arg default is true
		t.Options["compression"] = json.RawMessage(`true`)
	} else if value == "off" {
		t.Options["compression"] = json.RawMessage(`false`)
	} else { // arg was given check it
		var err error
		_, err = strconv.ParseBool(value)
		if err != nil {
			return d.Errf(`parsing compression value %+v: %w`, value, err)
		}
		t.Options["compression"] = json.RawMessage(value)
	}

	return nil
}

func (t *HTTP) unmarshalAllowCidr(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	current, exists := t.Options["allow_cidr"]
	if !exists {
		bs, err := json.Marshal(args)
		if err != nil {
			return err
		}
		t.Options["allow_cidr"] = json.RawMessage(bs)
		return nil
	}

	currentCIDR := bytes.Trim(current, "]")
	buf := bytes.NewBuffer(currentCIDR)

	buf.WriteString(",")
	for _, v := range args {
		buf.WriteString(`"` + v + `"`)
	}
	buf.WriteString("]")
	t.Options["allow_cidr"] = json.RawMessage(buf.Bytes())
	return nil
}

func (t *HTTP) unmarshalDenyCidr(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	current, exists := t.Options["deny_cidr"]
	if !exists {
		bs, err := json.Marshal(args)
		if err != nil {
			return err
		}
		t.Options["deny_cidr"] = json.RawMessage(bs)
		return nil
	}

	currentCIDR := bytes.Trim(current, "]")
	buf := bytes.NewBuffer(currentCIDR)

	buf.WriteString(",")
	for _, v := range args {
		buf.WriteString(`"` + v + `"`)
	}
	buf.WriteString("]")
	t.Options["deny_cidr"] = json.RawMessage(buf.Bytes())
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

	_, err := strconv.ParseFloat(ratio, 64)
	if err != nil {
		return d.ArgErr()
	}
	t.Options["circuit_breaker"] = json.RawMessage(ratio)
	return nil
}

var (
	_ caddy.Module          = (*HTTP)(nil)
	_ Tunnel                = (*HTTP)(nil)
	_ caddy.Provisioner     = (*HTTP)(nil)
	_ caddyfile.Unmarshaler = (*HTTP)(nil)
)
