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
			name: "default",
			input: `labeled {
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{}},
		},
		{
			name: "simple-inline",
			input: `labeled {
				label foo bar
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"foo": "bar"}},
		},
		{
			name: "simple-block",
			input: `labeled {
				label {
					foo bar
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"foo": "bar"}},
		},
		{
			name: "mulitple-inline",
			input: `labeled {
				label foo bar
				label spam eggs
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"foo": "bar", "spam": "eggs"}},
		},
		{
			name: "mulitple-block",
			input: `labeled {
				label {
					foo bar
					spam eggs
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"foo": "bar", "spam": "eggs"}},
		},
		{
			name: "mulitple-mixed",
			input: `labeled {
				label foo bar
				label {
					spam eggs
				}
			}`,
			shouldErr: false,
			expected:  Labeled{Labels: map[string]string{"foo": "bar", "spam": "eggs"}},
		},
		{
			name: "label-too-many-args",
			input: `labeled {
				label foo bar toomanyargs
			}`,
			shouldErr: true,
			expected:  Labeled{Labels: map[string]string{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			tun := Labeled{}
			err := tun.UnmarshalCaddyfile(d)
			tun.Provision(caddy.Context{})

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected error but found nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but found error: %v", err)
				} else if !reflect.DeepEqual(test.expected.Labels, tun.Labels) {
					t.Errorf("Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", tun, test.expected)
				}
			}
		})
	}
}

func TestLabeledMetadata(t *testing.T) {
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			tun := Labeled{}
			err := tun.UnmarshalCaddyfile(d)
			tun.Provision(caddy.Context{})

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected error but found nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but found error: %v", err)
				} else if test.expected.Metadata != tun.Metadata {
					t.Errorf("Created Labeled (\n%#v\n) does not match expected (\n%#v\n)", tun.Metadata, test.expected.Metadata)
				}
			}
		})
	}
}
