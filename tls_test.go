package ngroklistener

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/require"
)

func TestParseTLS(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TLS
	}{
		{
			name: "default",
			input: `tls {
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			tun := TLS{}
			err := tun.UnmarshalCaddyfile(d)
			tun.Provision(caddy.Context{})

			if test.shouldErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestTLSDomain(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TLS
	}{
		{
			name: "absent",
			input: `tls {
			}`,
			shouldErr: false,
			expected:  TLS{Domain: ""},
		},
		{
			name: "with domain",
			input: `tls {
				domain foo.ngrok.io
			}`,
			shouldErr: false,
			expected:  TLS{Domain: "foo.ngrok.io"},
		},
		{
			name: "domain-no-args",
			input: `tls {
				domain
			}`,
			shouldErr: true,
			expected:  TLS{Domain: ""},
		},
		{
			name: "domain-too-many-args",
			input: `tls {
				domain foo.ngrok.io foo.ngrok.io
			}`,
			shouldErr: true,
			expected:  TLS{Domain: ""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			tun := TLS{}
			err := tun.UnmarshalCaddyfile(d)
			tun.Provision(caddy.Context{})

			if test.shouldErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
				require.Equal(t, test.expected.Domain, tun.Domain)
			}
		})
	}
}

func TestTLSMetadata(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TLS
	}{
		{
			name: "absent",
			input: `tls {
			}`,
			shouldErr: false,
			expected:  TLS{Metadata: ""},
		},
		{
			name: "with metadata",
			input: `tls {
				metadata test
			}`,
			shouldErr: false,
			expected:  TLS{Metadata: "test"},
		},
		{
			name: "metadata-single-arg-quotes",
			input: `tls {
				metadata "Hello, World!"
			}`,
			shouldErr: false,
			expected:  TLS{Metadata: "Hello, World!"},
		},
		{
			name: "metadata-no-args",
			input: `tls {
				metadata
			}`,
			shouldErr: true,
			expected:  TLS{Metadata: ""},
		},
		{
			name: "metadata-too-many-args",
			input: `tls {
				metadata test test2
			}`,
			shouldErr: true,
			expected:  TLS{Metadata: ""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			tun := TLS{}
			err := tun.UnmarshalCaddyfile(d)
			tun.Provision(caddy.Context{})

			if test.shouldErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
				require.Equal(t, test.expected.Metadata, tun.Metadata)
			}
		})
	}
}

func TestTLSCIDRRestrictions(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TLS
	}{
		{
			name: "absent",
			input: `tls {
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "allow",
			input: `tls {
				allow 127.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{"127.0.0.0/8"}, DenyCIDR: []string{}},
		},
		{
			name: "deny",
			input: `tls {
				deny 127.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{"127.0.0.0/8"}},
		},
		{
			name: "allow multi",
			input: `tls {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}, DenyCIDR: []string{}},
		},
		{
			name: "allow multi inline",
			input: `tls {
				allow 127.0.0.0/8 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}, DenyCIDR: []string{}},
		},
		{
			name: "deny multi",
			input: `tls {
				deny 127.0.0.0/8
				deny 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}},
		},
		{
			name: "deny multi inline",
			input: `tls {
				deny 127.0.0.0/8 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}},
		},
		{
			name: "allow and deny multi",
			input: `tls {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
				deny 192.0.0.0/8
				deny 172.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TLS{AllowCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}, DenyCIDR: []string{"192.0.0.0/8", "172.0.0.0/8"}},
		},
		{
			name: "allow-no-args",
			input: `tls {
				allow
			}`,
			shouldErr: true,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "deny-no-args",
			input: `tls {
				deny
			}`,
			shouldErr: true,
			expected:  TLS{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			tun := TLS{}
			err := tun.UnmarshalCaddyfile(d)
			tun.Provision(caddy.Context{})

			if test.shouldErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
				require.ElementsMatch(t, test.expected.AllowCIDR, tun.AllowCIDR)
				require.ElementsMatch(t, test.expected.DenyCIDR, tun.DenyCIDR)
			}
		})
	}
}
