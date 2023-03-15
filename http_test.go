package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseHTTP(t *testing.T) {
	class := "ParseHTTP"

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
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.Metadata != tun.Metadata {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Metadata, test.expected.Metadata)
			} else if test.expected.Domain != tun.Domain {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Domain, test.expected.Domain)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.DenyCIDR, test.expected.DenyCIDR)
			} else if test.expected.Compression != tun.Compression {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Compression, test.expected.Compression)
			} else if test.expected.WebsocketTCPConverter != tun.WebsocketTCPConverter {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.WebsocketTCPConverter, test.expected.WebsocketTCPConverter)
			}
		}
	}
}

func TestHTTPBasicAuth(t *testing.T) {
	class := "HTTPBasicAuth"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  HTTP
	}{
		{
			name: "empty",
			input: `http {
			}`,
			shouldErr: false,
			expected:  HTTP{BasicAuth: map[string]string{}},
		},
		{
			name: "single-inline",
			input: `http {
				basic_auth foo barbarbar
			}`,
			shouldErr: false,
			expected:  HTTP{BasicAuth: map[string]string{"foo": "barbarbar"}},
		},
		{
			name: "single-block",
			input: `http {
				basic_auth {
					foo barbarbar
				}
			}`,
			shouldErr: false,
			expected:  HTTP{BasicAuth: map[string]string{"foo": "barbarbar"}},
		},
		{
			name: "multiple",
			input: `http {
				basic_auth foo barbarbar
				basic_auth spam eggsandcheese
				basic_auth {
					bar bazbazbaz
					bam bambinos
				}
			}`,
			shouldErr: false,
			expected:  HTTP{BasicAuth: map[string]string{"bam": "bambinos", "bar": "bazbazbaz", "foo": "barbarbar", "spam": "eggsandcheese"}},
		},
		{
			name: "password-too-short",
			input: `http {
				basic_auth foo bar
			}`,
			shouldErr: true,
			expected:  HTTP{BasicAuth: map[string]string{}},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := HTTP{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if !reflect.DeepEqual(test.expected.BasicAuth, tun.BasicAuth) {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.BasicAuth, test.expected.BasicAuth)
			}
		}
	}
}

func TestHTTPCircuitBreaker(t *testing.T) {
	class := "HTTPCircuitBreaker"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  HTTP
	}{
		{
			name: "absent",
			input: `http {
			}`,
			shouldErr: false,
			expected:  HTTP{CircuitBreaker: 0},
		},
		{
			name: "breakered",
			input: `http {
				circuit_breaker 0.5
			}`,
			shouldErr: false,
			expected:  HTTP{CircuitBreaker: 0.5},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := HTTP{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.CircuitBreaker != tun.CircuitBreaker {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.CircuitBreaker, test.expected.CircuitBreaker)
			}
		}
	}
}

func TestHTTPCompression(t *testing.T) {
	class := "HTTPCompression"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  HTTP
	}{
		{
			name: "absent",
			input: `http {
			}`,
			shouldErr: false,
			expected:  HTTP{Compression: false},
		},
		{
			name: "compressed-off",
			input: `http {
				compression off
			}`,
			shouldErr: false,
			expected:  HTTP{Compression: false},
		},
		{
			name: "compressed-false",
			input: `http {
				compression false
			}`,
			shouldErr: false,
			expected:  HTTP{Compression: false},
		},
		{
			name: "compressed-true",
			input: `http {
				compression true
			}`,
			shouldErr: false,
			expected:  HTTP{Compression: true},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := HTTP{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.Compression != tun.Compression {
				t.Errorf("Test %v (%v) %v: Created HTTP (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Compression, test.expected.Compression)
			}
		}
	}
}
