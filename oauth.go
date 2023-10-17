package ngroklistener

import (
	"errors"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

type oauth struct {
	opts []config.OAuthOption
	opt  config.HTTPEndpointOption

	Provider     string   `json:"provider,omitempty"`
	AllowEmails  []string `json:"allow_emails,omitempty"`
	AllowDomains []string `json:"allow_domains,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

func (o *oauth) Provision(caddy.Context) error {
	o.doReplace()

	if len(o.AllowEmails) > 0 {
		o.opts = append(o.opts, config.WithAllowOAuthEmail(o.AllowEmails...))
	}

	if len(o.AllowDomains) > 0 {
		o.opts = append(o.opts, config.WithAllowOAuthDomain(o.AllowDomains...))
	}

	if len(o.Scopes) > 0 {
		o.opts = append(o.opts, config.WithOAuthScope(o.Scopes...))
	}

	if strings.TrimSpace(o.Provider) == "" {
		return errors.New("oauth `provider` cannot be empty string")
	}

	o.opt = config.WithOAuth(o.Provider, o.opts...)

	return nil
}

func (o *oauth) doReplace() {
	repl := caddy.NewReplacer()

	replacedAllowEmails := make([]string, len(o.AllowEmails))

	for index, email := range o.AllowEmails {
		actual := repl.ReplaceKnown(email, "")

		replacedAllowEmails[index] = actual
	}

	o.AllowEmails = replacedAllowEmails

	replacedAllowDomains := make([]string, len(o.AllowDomains))

	for index, domain := range o.AllowDomains {
		actual := repl.ReplaceKnown(domain, "")

		replacedAllowDomains[index] = actual
	}

	o.AllowDomains = replacedAllowDomains

	replacedScopes := make([]string, len(o.Scopes))

	for index, scope := range o.Scopes {
		actual := repl.ReplaceKnown(scope, "")

		replacedScopes[index] = actual
	}

	o.Scopes = replacedScopes

	o.Provider = repl.ReplaceKnown(o.Provider, "")

}

func (o *oauth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		switch subdirective {
		case "provider":
			if !d.AllArgs(&o.Provider) {
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

func (o *oauth) unmarshalScopes(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	o.Scopes = append(o.Scopes, d.RemainingArgs()...)

	return nil
}

func (o *oauth) unmarshalAllowDomains(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	o.AllowDomains = append(o.AllowDomains, d.RemainingArgs()...)

	return nil
}

func (o *oauth) unmarshalAllowEmails(d *caddyfile.Dispenser) error {
	if d.CountRemainingArgs() == 0 {
		return d.ArgErr()
	}

	o.AllowEmails = append(o.AllowEmails, d.RemainingArgs()...)

	return nil
}
