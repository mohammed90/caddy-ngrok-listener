package ngroklistener

import (
	"errors"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

type oidc struct {
	opts       []config.OIDCOption
	OIDCOption config.HTTPEndpointOption

	IssuerURL    string   `json:"issuer_url,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	AllowEmails  []string `json:"allow_emails,omitempty"`
	AllowDomains []string `json:"allow_domains,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

func (o *oidc) Provision(caddy.Context) error {
	o.doReplace()

	if len(o.AllowEmails) > 0 {
		o.opts = append(o.opts, config.WithAllowOIDCEmail(o.AllowEmails...))
	}

	if len(o.AllowDomains) > 0 {
		o.opts = append(o.opts, config.WithAllowOIDCDomain(o.AllowDomains...))
	}

	if len(o.Scopes) > 0 {
		o.opts = append(o.opts, config.WithOIDCScope(o.Scopes...))
	}

	if strings.TrimSpace(o.IssuerURL) == "" {
		return errors.New("oidc `issuer_url` cannot be empty string")
	}

	if strings.TrimSpace(o.ClientID) == "" {
		return errors.New("oidc `client_id` cannot be empty string")
	}

	if strings.TrimSpace(o.ClientSecret) == "" {
		return errors.New("oidc `client_secret` cannot be empty string")
	}

	o.OIDCOption = config.WithOIDC(o.IssuerURL, o.ClientID, o.ClientSecret, o.opts...)

	return nil
}

func (o *oidc) doReplace() {
	repl := caddy.NewReplacer()

	for index, email := range o.AllowEmails {
		actual := repl.ReplaceKnown(email, "")
		o.AllowEmails[index] = actual
	}

	for index, domain := range o.AllowDomains {
		actual := repl.ReplaceKnown(domain, "")
		o.AllowDomains[index] = actual
	}

	for index, scopes := range o.Scopes {
		actual := repl.ReplaceKnown(scopes, "")
		o.Scopes[index] = actual
	}

	o.IssuerURL = repl.ReplaceKnown(o.IssuerURL, "")
	o.ClientID = repl.ReplaceKnown(o.ClientID, "")
	o.ClientSecret = repl.ReplaceKnown(o.ClientSecret, "")

}

func (o *oidc) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		switch subdirective {
		case "issuer_url":
			if !d.AllArgs(&o.IssuerURL) {
				return d.ArgErr()
			}
		case "client_id":
			if !d.AllArgs(&o.ClientID) {
				return d.ArgErr()
			}
		case "client_secret":
			if !d.AllArgs(&o.ClientSecret) {
				return d.ArgErr()
			}
		case "scopes":
			if err := o.unmarshalScopes(d); err != nil {
				return err
			}
		case "allow_domains":
			if err := o.unmarshalAllowDomains(d); err != nil {
				return err
			}
		case "allow_emails":
			if err := o.unmarshalAllowEmails(d); err != nil {
				return err
			}
		default:
			return d.Errf("unrecognized subdirective %s", subdirective)
		}
	}

	return nil
}

func (o *oidc) unmarshalScopes(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	o.Scopes = append(o.Scopes, d.RemainingArgs()...)

	return nil
}

func (o *oidc) unmarshalAllowDomains(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	o.AllowDomains = append(o.AllowDomains, d.RemainingArgs()...)

	return nil
}

func (o *oidc) unmarshalAllowEmails(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	o.AllowEmails = append(o.AllowEmails, d.RemainingArgs()...)

	return nil
}
