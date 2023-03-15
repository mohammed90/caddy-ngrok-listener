package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseTCP(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  TCP
	}{
		{
			name: "",
			input: `tcp {
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				allow 1
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{"1"}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				allow 1 2 3
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{"1", "2", "3"}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				allow
			}`,
			shouldErr: true,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				deny 1
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{"1"}},
		},
		{
			name: "",
			input: `tcp {
				deny 1 2 3
			}`,
			shouldErr: false,
			expected:  TCP{AllowCIDR: []string{}, DenyCIDR: []string{"1", "2", "3"}},
		},
		{
			name: "",
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
				t.Errorf("Test (%v) %v: Expected error but found nil", i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test (%v) %v: Expected no error but found error: %v", i, test.name, err)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.DenyCIDR, test.expected.DenyCIDR)
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
