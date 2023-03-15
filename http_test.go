package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseHTTP(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  HTTP
	}{
		{
			name: "",
			input: `http {
				metadata test
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				domain test.domain.com
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", Domain: "test.domain.com", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				domain
			}`,
			shouldErr: true,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				domain too manyargs
			}`,
			shouldErr: true,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				allow 1
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{"1"}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				allow 1 2 3
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{"1", "2", "3"}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				allow
			}`,
			shouldErr: true,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				deny 1
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1"}},
		},
		{
			name: "",
			input: `http {
				metadata test
				deny 1 2 3
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1", "2", "3"}},
		},
		{
			name: "",
			input: `http {
				metadata test
				deny
			}`,
			shouldErr: true,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `http {
				metadata test
				compression
				websocket_tcp_converter
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}, Compression: true, WebsocketTCPConverter: true},
		},
		{
			name: "",
			input: `http {
				metadata test
				compression true
				websocket_tcp_converter true
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}, Compression: true, WebsocketTCPConverter: true},
		},
		{
			name: "",
			input: `http {
				metadata test
				compression false
				websocket_tcp_converter false
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}, Compression: false, WebsocketTCPConverter: false},
		},
		{
			name: "",
			input: `http {
				metadata test
				compression off
				websocket_tcp_converter off
			}`,
			shouldErr: false,
			expected:  HTTP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}, Compression: false, WebsocketTCPConverter: false},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := HTTP{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test (%v) %v: Expected error but found nil", i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test (%v) %v: Expected no error but found error: %v", i, test.name, err)
			} else if test.expected.Metadata != tun.Metadata {
				t.Errorf("Test (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.Metadata, test.expected.Metadata)
			} else if test.expected.Domain != tun.Domain {
				t.Errorf("Test (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.Domain, test.expected.Domain)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.DenyCIDR, test.expected.DenyCIDR)
			} else if test.expected.Compression != tun.Compression {
				t.Errorf("Test (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.Compression, test.expected.Compression)
			} else if test.expected.WebsocketTCPConverter != tun.WebsocketTCPConverter {
				t.Errorf("Test (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.WebsocketTCPConverter, test.expected.WebsocketTCPConverter)
			}
		}
	}
}
