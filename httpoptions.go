package ngroklistener

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"golang.ngrok.com/ngrok/config"
)

func init() {
	caddy.RegisterModule(AllowCIDR{})
	caddy.RegisterModule(DenyCIDR{})
	caddy.RegisterModule(HTTPDomain(""))
	caddy.RegisterModule(HTTPMetadata(""))
	caddy.RegisterModule(HTTPScheme(""))
	caddy.RegisterModule(HTTPCircuitBreaker(0))
	caddy.RegisterModule(HTTPCompression(false))
	caddy.RegisterModule(HTTPWebsocketTCPConversion(false))
}

type HTTPOptioner interface {
	HTTPOption() config.HTTPEndpointOption
}

// Rejects connections that do not match the given CIDRs
type AllowCIDR []string

// Provision implements caddy.Provisioner
func (ac *AllowCIDR) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	for index, cidr := range *ac {
		actual := repl.ReplaceKnown(cidr, "")
		(*ac)[index] = actual
	}
	return nil
}

// CaddyModule implements caddy.Module
func (AllowCIDR) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.allow_cidr",
		New: func() caddy.Module {
			return new(AllowCIDR)
		},
	}
}
func (a AllowCIDR) HTTPOption() config.HTTPEndpointOption {
	if len(a) <= 0 {
		return nil
	}
	return config.WithAllowCIDRString(a...)
}

// Rejects connections that match the given CIDRs and allows all other CIDRs.
type DenyCIDR []string

// Provision implements caddy.Provisioner
func (dc *DenyCIDR) Provision(caddy.Context) error {
	repl := caddy.NewReplacer()
	for index, cidr := range *dc {
		actual := repl.ReplaceKnown(cidr, "")
		(*dc)[index] = actual
	}
	return nil
}

// CaddyModule implements caddy.Module
func (DenyCIDR) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.deny_cidr",
		New: func() caddy.Module {
			return new(DenyCIDR)
		},
	}
}
func (a DenyCIDR) HTTPOption() config.HTTPEndpointOption {
	if len(a) <= 0 {
		return nil
	}
	return config.WithDenyCIDRString(a...)
}

// the domain for this edge
type HTTPDomain string

// Provision implements caddy.Provisioner
func (hd HTTPDomain) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	hd = HTTPDomain(repl.ReplaceKnown(string(hd), ""))
	return nil
}

func (HTTPDomain) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.domain",
		New: func() caddy.Module {
			return new(HTTPDomain)
		},
	}
}
func (a HTTPDomain) HTTPOption() config.HTTPEndpointOption {
	return config.WithDomain(string(a))
}

// opaque metadata string for this tunnel
type HTTPMetadata string

func (HTTPMetadata) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.metadata",
		New: func() caddy.Module {
			return new(HTTPMetadata)
		},
	}
}

// Provision implements caddy.Provisioner
func (hm HTTPMetadata) Provision(caddy.Context) error {
	repl := caddy.NewReplacer()
	hm = HTTPMetadata(repl.ReplaceKnown(string(hm), ""))
	return nil
}

func (a HTTPMetadata) HTTPOption() config.HTTPEndpointOption {
	return config.WithMetadata(string(a))
}

// sets the scheme for this edge
type HTTPScheme string

// Provision implements caddy.Provisioner
func (hs HTTPScheme) Provision(caddy.Context) error {
	repl := caddy.NewReplacer()
	hs = HTTPScheme(repl.ReplaceKnown(string(hs), ""))
	return nil
}

func (HTTPScheme) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.scheme",
		New: func() caddy.Module {
			return new(HTTPScheme)
		},
	}
}

func (a HTTPScheme) Validate() error {
	switch s := strings.ToLower(strings.TrimSpace(string(a))); s {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("unrecognized http tunnel scheme: %s", a)
	}
}

func (a HTTPScheme) HTTPOption() config.HTTPEndpointOption {
	var scheme config.Scheme
	switch s := strings.ToLower(strings.TrimSpace(string(a))); s {
	case "http":
		scheme = config.SchemeHTTP
	case "https":
		scheme = config.SchemeHTTPS
	}
	return config.WithScheme(scheme)
}

// the 5XX response ratio at which the ngrok edge will stop sending requests to this tunnel.
type HTTPCircuitBreaker float64

// CaddyModule implements caddy.Module
func (HTTPCircuitBreaker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.circuit_breaker",
		New: func() caddy.Module {
			return new(HTTPCircuitBreaker)
		},
	}
}

// HTTPOption implements HTTPOptioner
func (hcb HTTPCircuitBreaker) HTTPOption() config.HTTPEndpointOption {
	return config.WithCircuitBreaker(float64(hcb))
}

// enables gzip compression
type HTTPCompression bool

// CaddyModule implements caddy.Module
func (HTTPCompression) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.compression",
		New: func() caddy.Module {
			return new(HTTPCompression)
		},
	}
}

// HTTPOption implements HTTPOptioner
func (hc HTTPCompression) HTTPOption() config.HTTPEndpointOption {
	if hc {
		return config.WithCompression()
	}
	return nil
}

// enables the websocket-to-tcp converter
type HTTPWebsocketTCPConversion bool

// CaddyModule implements caddy.Module
func (HTTPWebsocketTCPConversion) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.listeners.ngrok.tunnels.http.options.websocket_tcp_conversion",
		New: func() caddy.Module {
			return new(HTTPWebsocketTCPConversion)
		},
	}
}

// HTTPOption implements HTTPOptioner
func (hwtc HTTPWebsocketTCPConversion) HTTPOption() config.HTTPEndpointOption {
	if hwtc {
		return config.WithWebsocketTCPConversion()
	}
	return nil
}

var _ caddy.Module = AllowCIDR{}
var _ caddy.Provisioner = &AllowCIDR{}
var _ HTTPOptioner = AllowCIDR{}
var _ caddy.Module = DenyCIDR{}
var _ caddy.Provisioner = &DenyCIDR{}
var _ HTTPOptioner = DenyCIDR{}
var _ caddy.Module = HTTPDomain("")
var _ caddy.Provisioner = HTTPDomain("")
var _ HTTPDomain = HTTPDomain("")
var _ caddy.Module = HTTPMetadata("")
var _ caddy.Provisioner = HTTPMetadata("")
var _ HTTPOptioner = HTTPMetadata("")
var _ caddy.Module = HTTPScheme("")
var _ caddy.Provisioner = HTTPScheme("")
var _ caddy.Validator = HTTPScheme("")
var _ HTTPOptioner = HTTPScheme("")
var _ caddy.Module = HTTPCircuitBreaker(0)
var _ HTTPOptioner = HTTPCircuitBreaker(0)
var _ caddy.Module = HTTPCompression(false)
var _ HTTPOptioner = HTTPCompression(false)
var _ caddy.Module = HTTPWebsocketTCPConversion(false)
var _ HTTPOptioner = HTTPWebsocketTCPConversion(false)
