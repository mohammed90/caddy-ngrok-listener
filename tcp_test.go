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
				metadata test
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
				allow 1
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{"1"}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
				allow 1 2 3
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{"1", "2", "3"}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
				allow
			}`,
			shouldErr: true,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
				deny 1
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1"}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
				deny 1 2 3
			}`,
			shouldErr: false,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1", "2", "3"}},
		},
		{
			name: "",
			input: `tcp {
				metadata test
				deny
			}`,
			shouldErr: true,
			expected:  TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}},
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
			} else if test.expected.Metadata != tun.Metadata {
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.Metadata, test.expected.Metadata)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test (%v) %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun.DenyCIDR, test.expected.DenyCIDR)
			}
		}
	}
}
