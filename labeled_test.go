package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseLabeled(t *testing.T) {
	class := "ParseLabeled"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  Labeled
	}{
		{
			name: "default",
			input: `labeled {
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{}},
		},
		{
			name: "",
			input: `labeled {
				label test me
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"test": "me"}},
		},
		{
			name: "",
			input: `labeled {
				label test me
				label test2 metoo
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"test": "me", "test2": "metoo"}},
		},
		{
			name: "",
			input: `labeled {
				label {
					blocks aswell
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"blocks": "aswell"}},
		},
		{
			name: "",
			input: `labeled {
				label {
					test me
					test2 metoo
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"test": "me", "test2": "metoo"}},
		},
		{
			name: "",
			input: `labeled {
				label {
					test me
					test2 metoo
				}
				label inline works
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"test": "me", "test2": "metoo", "inline": "works"}},
		},
		{
			name: "",
			input: `labeled {
				label inline works toomanyargs
			}`,
			shouldErr: true,
			expected:  Labeled{Labels: map[string]string{"inline": "works"}},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := Labeled{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if !reflect.DeepEqual(test.expected.Labels, tun.Labels) {
				t.Errorf("Test %v (%v) %v: Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun, test.expected)
			}
		}
	}
}

func TestLabeledMetadata(t *testing.T) {
	class := "LabeledMetadata"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  Labeled
	}{
		{
			name: "absent",
			input: `labeled {
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: ""},
		},
		{
			name: "with metadata",
			input: `labeled {
				metadata test
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "test"},
		},
		{
			name: "metadata-single-arg-quotes",
			input: `labeled {
				metadata "Hello, World!"
			}`,
			shouldErr: false,
			expected:  Labeled{Metadata: "Hello, World!"},
		},
		{
			name: "metadata-no-args",
			input: `labeled {
				metadata
			}`,
			shouldErr: true,
			expected:  Labeled{Metadata: ""},
		},
		{
			name: "metadata-too-many-args",
			input: `labeled {
				metadata test test2
			}`,
			shouldErr: true,
			expected:  Labeled{Metadata: ""},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := Labeled{}
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
				t.Errorf("Test %v (%v) %v: Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, tun.Metadata, test.expected.Metadata)
			}
		}
	}
}
