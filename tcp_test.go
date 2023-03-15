package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseTCP(t *testing.T) {
	class := "ParseTCP"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TCP
	}{
		{
			name: "default",
			input: `tcp {
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "remote addr",
			input: `tcp {
				remote_addr 0.tcp.ngrok.io:1234
			}`,
			shouldErr: false,
			expected:  TCP{RemoteAddr: "0.tcp.ngrok.io:1234", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TCP{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.RemoteAddr != tun.RemoteAddr {
				t.Errorf("Test %v (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.RemoteAddr, test.expected.RemoteAddr)
			}
		}
	}
}

func TestTCPMetadata(t *testing.T) {
	class := "TCPMetadata"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TCP
	}{
		{
			name: "absent",
			input: `tcp {
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: ""},
		},
		{
			name: "with metadata",
			input: `tcp {
				metadata test
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test"},
		},
		{
			name: "metadata-single-arg-quotes",
			input: `tcp {
				metadata "Hello, World!"
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "Hello, World!"},
		},
		{
			name: "metadata-no-args",
			input: `tcp {
				metadata
			}`,
			shouldErr: true,
			expected:  TCP{Metadata: ""},
		},
		{
			name: "metadata-too-many-args",
			input: `tcp {
				metadata test test2
			}`,
			shouldErr: true,
			expected:  TCP{Metadata: ""},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TCP{}
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
				t.Errorf("Test %v (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Metadata, test.expected.Metadata)
			}
		}
	}
}

func TestTCPCIDRRestrictions(t *testing.T) {
	class := "TCPCIDRRestrictions"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TCP
	}{
		{
			name: "absent",
			input: `tcp {
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "allow",
			input: `tcp {
				allow 127.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{"127.0.0.0/8"}, DenyCIDR: []string{}},
		},
		{
			name: "deny",
			input: `tcp {
				deny 127.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{"127.0.0.0/8"}},
		},
		{
			name: "allow multi",
			input: `tcp {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}, DenyCIDR: []string{}},
		},
		{
			name: "allow multi inline",
			input: `tcp {
				allow 127.0.0.0/8 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}, DenyCIDR: []string{}},
		},
		{
			name: "deny multi",
			input: `tcp {
				deny 127.0.0.0/8
				deny 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}},
		},
		{
			name: "deny multi inline",
			input: `tcp {
				deny 127.0.0.0/8 10.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}},
		},
		{
			name: "allow and deny multi",
			input: `tcp {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
				deny 192.0.0.0/8
				deny 172.0.0.0/8
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}, DenyCIDR: []string{"192.0.0.0/8", "172.0.0.0/8"}},
		},
		{
			name: "allow-no-args",
			input: `tcp {
				allow
			}`,
			shouldErr: true,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "deny-no-args",
			input: `tcp {
				deny
			}`,
			shouldErr: true,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TCP{}
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
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.DenyCIDR, test.expected.DenyCIDR)
			}
		}
	}
}
