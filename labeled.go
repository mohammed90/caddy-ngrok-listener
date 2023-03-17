package ngroklistener

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(new(Labeled))
}

// ngrok Labeled Tunnel
type Labeled struct {
	opts []config.LabeledTunnelOption

	// A map of label, value pairs for this tunnel.
	Labels map[string]string `json:"labels,omitempty"`

	// opaque metadata string for this tunnel.
	Metadata string `json:"metadata,omitempty"`

	l *zap.Logger
}

// CaddyModule implements caddy.Module
func (*Labeled) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.labeled",
		New: func() caddy.Module {
			return new(Labeled)
		},
	}
}

// Provision implements caddy.Provisioner
func (t *Labeled) Provision(ctx caddy.Context) error {
	t.l = ctx.Logger()

	if err := t.doReplace(); err != nil {
		return fmt.Errorf("loading doing replacements: %v", err)
	}

	if err := t.provisionOpts(); err != nil {
		return fmt.Errorf("provisioning labeled tunnel opts: %v", err)
	}

	if t.Labels == nil || len(t.Labels) == 0 {
		return fmt.Errorf("a label is required for labeled tunnels")
	}

	return nil
}

func (t *Labeled) provisionOpts() error {
	for label, value := range t.Labels {
		t.opts = append(t.opts, config.WithLabel(label, value))
		t.l.Info("applying label", zap.String("label", label), zap.String("value", value))
	}

	if t.Metadata != "" {
		t.opts = append(t.opts, config.WithMetadata(t.Metadata))
	}

	return nil
}

func (t *Labeled) doReplace() error {
	repl := caddy.NewReplacer()
	replaceableFields := []*string{
		&t.Metadata,
	}

	for _, field := range replaceableFields {
		actual := repl.ReplaceKnown(*field, "")
		*field = actual
	}

	replacedLabels := make(map[string]string)

	for labelName, labelValue := range t.Labels {
		actualLabelName := repl.ReplaceKnown(labelName, "")
		actualLabelValue := repl.ReplaceKnown(labelValue, "")

		replacedLabels[actualLabelName] = actualLabelValue
	}

	t.Labels = replacedLabels

	return nil
}

// convert to ngrok's Tunnel type
func (t *Labeled) NgrokTunnel() config.Tunnel {
	return config.LabeledTunnel(t.opts...)
}

func (t *Labeled) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
			case "label":
				if err := t.unmarshalLabels(d); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized subdirective %s", subdirective)
			}
		}
	}

	return nil
}

func (t *Labeled) unmarshalLabels(d *caddyfile.Dispenser) error {
	var (
		label      string
		labelValue string
	)

	if t.Labels == nil {
		t.Labels = map[string]string{}
	}

	label = d.Val()

	if d.CountRemainingArgs() != 0 { // label is defined inline
		if !d.AllArgs(&label, &labelValue) {
			return d.ArgErr()
		}

		t.Labels[label] = labelValue

		return nil
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); { // block of labels
		label := d.Val()

		if !d.AllArgs(&labelValue) {
			return d.ArgErr()
		}

		t.Labels[label] = labelValue
	}

	return nil
}

var (
	_ caddy.Module          = (*Labeled)(nil)
	_ Tunnel                = (*Labeled)(nil)
	_ caddy.Provisioner     = (*Labeled)(nil)
	_ caddyfile.Unmarshaler = (*Labeled)(nil)
)
