package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseTLS(t *testing.T) {
	class := "ParseTLS"

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

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TLS{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			}
		}
	}
}

func TestTLSDomain(t *testing.T) {
	class := "TLSDomain"

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

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TLS{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.Domain != tun.Domain {
				t.Errorf("Test %v (%v) %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Domain, test.expected.Domain)
			}
		}
	}
}

func TestTLSMetadata(t *testing.T) {
	class := "TLSMetadata"

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

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TLS{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.Metadata != tun.Metadata {
				t.Errorf("Test %v (%v) %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Metadata, test.expected.Metadata)
			}
		}
	}
}

func TestTLSCIDRRestrictions(t *testing.T) {
	class := "TLSCIDRRestrictions"

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

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TLS{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test (%v) %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test (%v) %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.DenyCIDR, test.expected.DenyCIDR)
			}
		}
	}
}
