package ngroklistener

import (
	"errors"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

type webhookVerification struct {
	WebhookVerificationOption config.HTTPEndpointOption

	Provider string `json:"provider,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

func (wv *webhookVerification) Provision(caddy.Context) error {

	wv.doReplace()

	if strings.TrimSpace(wv.Provider) == "" {
		return errors.New("webhookVerification `provider` cannot be empty string")
	}

	if strings.TrimSpace(wv.Secret) == "" {
		return errors.New("webhookVerification `secret` cannot be empty string")
	}

	wv.WebhookVerificationOption = config.WithWebhookVerification(wv.Provider, wv.Secret)

	return nil
}

func (wv *webhookVerification) doReplace() {

	repl := caddy.NewReplacer()

	wv.Provider = repl.ReplaceKnown(wv.Provider, "")

	wv.Secret = repl.ReplaceKnown(wv.Secret, "")

}

func (wv *webhookVerification) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		switch subdirective {
		case "provider":
			if !d.AllArgs(&wv.Provider) {
				return d.ArgErr()
			}
		case "secret":
			if !d.AllArgs(&wv.Secret) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective %s", subdirective)
		}
	}

	return nil
}
