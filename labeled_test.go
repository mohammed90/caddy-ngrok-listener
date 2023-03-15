package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseLabeled(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  Labeled
	}{
		{
			name: "",
			input: `labeled {
				metadata test
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{}},
		},
		{
			name: "",
			input: `labeled {
				metadata test
				label test me
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{"test": "me"}},
		},
		{
			name: "",
			input: `labeled {
				metadata test
				label test me
				label test2 metoo
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{"test": "me", "test2": "metoo"}},
		},
		{
			name: "",
			input: `labeled {
				metadata test
				label {
					blocks aswell
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{"blocks": "aswell"}},
		},
		{
			name: "",
			input: `labeled {
				metadata test
				label {
					test me
					test2 metoo
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{"test": "me", "test2": "metoo"}},
		},
		{
			name: "",
			input: `labeled {
				metadata test
				label {
					test me
					test2 metoo
				}
				label inline works
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{"test": "me", "test2": "metoo", "inline": "works"}},
		},
		{
			name: "",
			input: `labeled {
				label inline works toomanyargs
			}`,
			shouldErr: true,
			expected:  Labeled{Metadata: "test", Labels: map[string]string{"inline": "works"}},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := Labeled{}
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
				t.Errorf("Test (%v) %v: Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun, test.expected)
			} else if !reflect.DeepEqual(test.expected.Labels, tun.Labels) {
				t.Errorf("Test (%v) %v: Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, tun, test.expected)
			}
		}
	}
}
