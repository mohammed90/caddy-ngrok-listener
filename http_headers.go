package ngroklistener

import (
	"errors"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.ngrok.com/ngrok/config"
)

type httpHeaders struct {
	opts []config.HTTPEndpointOption

	Added   map[string]string `json:"added,omitempty"`
	Removed []string          `json:"removed,omitempty"`
}

func (h *httpHeaders) provisionRequestHeaders() ([]config.HTTPEndpointOption, error) {

	for name, value := range h.Added {
		h.opts = append(h.opts, config.WithRequestHeader(name, value))
	}

	for _, name := range h.Removed {
		h.opts = append(h.opts, config.WithRemoveRequestHeader(name))
	}

	return h.opts, nil
}

func (h *httpHeaders) provisionResponseHeaders() ([]config.HTTPEndpointOption, error) {

	for name, value := range h.Added {
		h.opts = append(h.opts, config.WithResponseHeader(name, value))
	}

	for _, name := range h.Removed {
		h.opts = append(h.opts, config.WithRemoveResponseHeader(name))
	}

	return h.opts, nil
}

func (h *httpHeaders) doReplace(repl *caddy.Replacer) error {

	replacedAddedHeaders := make(map[string]string, len(h.Added))

	for name, value := range h.Added {
		actualName := repl.ReplaceKnown(name, "")

		actualValue := repl.ReplaceKnown(value, "")

		replacedAddedHeaders[actualName] = actualValue
	}

	h.Added = replacedAddedHeaders

	replacedRemovedHeaders := make([]string, len(h.Removed))

	for index, name := range h.Removed {
		actual := repl.ReplaceKnown(name, "")

		replacedRemovedHeaders[index] = actual
	}

	h.Removed = replacedRemovedHeaders

	return nil
}

func (h *httpHeaders) unmarshalHeaders(d *caddyfile.Dispenser) error {
	for d.Next() {
		// first see if headers are in the initial line
		var hasArgs bool
		if d.NextArg() {
			hasArgs = true
			field := d.Val()
			var value string
			if !d.AllArgs(&value) {
				d.ArgErr() // Additional arg Would be replacement if ngrok handled that
			}
			err := h.applyHeaderOp(
				field,
				value,
			)
			if err != nil {
				return d.Err(err.Error())
			}
		}

		// if not, they should be in a block
		for d.NextBlock(0) {
			field := d.Val()
			if hasArgs {
				return d.Err("cannot specify headers in both arguments and block") // because it would be weird
			}

			// sometimes it is habitual for users to suffix a field name with a colon,
			// as if they were writing a curl command or something; see
			// https://caddy.community/t/v2-reverse-proxy-please-add-cors-example-to-the-docs/7349/19
			field = strings.TrimSuffix(field, ":")

			var value string
			if !d.AllArgs(&value) {
				d.ArgErr() // Additional arg Would be replacement if ngrok handled that
			}
			err := h.applyHeaderOp(
				field,
				value,
			)
			if err != nil {
				return d.Err(err.Error())
			}
		}
	}

	return nil
}

func (h *httpHeaders) applyHeaderOp(field, value string) error {

	switch {
	case strings.HasPrefix(field, "+"): // append would be caddy standard but ngrok only handles overwrite
		if h.Added == nil {
			h.Added = map[string]string{}
		}
		h.Added[field[1:]] = value

	case strings.HasPrefix(field, "-"): // delete
		h.Removed = append(h.Removed, field[1:])
	case strings.HasPrefix(field, "?"): // default (conditional on not existing) - response headers only ngrok doesn't handle this type of operation.
		return errors.New("ngrok doesn't handle default header modifiers")
	default: // set (overwrite)
		if h.Added == nil {
			h.Added = map[string]string{}
		}
		h.Added[field] = value
	}

	return nil
}
