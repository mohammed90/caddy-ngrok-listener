package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseLabeled(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  Labeled
	}{
		{`labeled {
			metadata test
		}`, false, Labeled{Metadata: "test"}},
		{`labeled {
			metadata test
			label test me
		}`, false, Labeled{Metadata: "test", Labels: map[string]string{"test": "me"}}},
		{`labeled {
			metadata test
			label test me
			label test2 metoo
		}`, false, Labeled{Metadata: "test", Labels: map[string]string{"test": "me", "test2": "metoo"}}},
		{`labeled {
			metadata test
			label {
				blocks aswell
			}
		}`, false, Labeled{Metadata: "test", Labels: map[string]string{"blocks": "aswell"}}},
		{`labeled {
			metadata test
			label {
				test me
				test2 metoo
			}
		}`, false, Labeled{Metadata: "test", Labels: map[string]string{"test": "me", "test2": "metoo"}}},
		{`labeled {
			metadata test
			label {
				test me
				test2 metoo
			}
			label inline works
		}`, false, Labeled{Metadata: "test", Labels: map[string]string{"test": "me", "test2": "metoo", "inline": "works"}}},
		{`labeled {
			label inline works toomanyargs
		}`, true, Labeled{Metadata: "test", Labels: map[string]string{"inline": "works"}}},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := Labeled{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v: Expected error but found nil", i)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v: Expected no error but found error: %v", i, err)
			} else if test.expected.Metadata != tun.Metadata {
				t.Errorf("Test %v: Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", i, tun, test.expected)
			} else if !reflect.DeepEqual(test.expected.Labels, tun.Labels) {
				t.Errorf("Test %v: Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", i, tun, test.expected)
			}
		}
	}
}
