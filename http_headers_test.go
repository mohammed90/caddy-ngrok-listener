package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestHTTPHeaders(t *testing.T) {
	class := "HTTPHeaders"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  httpHeaders
	}{
		{
			name:      "absent",
			input:     `{}`,
			shouldErr: false,
			expected:  httpHeaders{Added: nil, Removed: nil},
		},
		{
			name:      "add header inline",
			input:     `header foo bar`,
			shouldErr: false,
			expected:  httpHeaders{Added: map[string]string{"foo": "bar"}, Removed: nil},
		},
		{
			name:      "remove header inline",
			input:     `header -baz`,
			shouldErr: false,
			expected:  httpHeaders{Added: nil, Removed: []string{"baz"}},
		},
		{
			name: "add headers inline",
			input: `
				header foo bar
				header spam eggs
			`,
			shouldErr: false,
			expected:  httpHeaders{Added: map[string]string{"foo": "bar", "spam": "eggs"}, Removed: nil},
		},
		{
			name: "remove headers inline",
			input: `
				header -qas
				header -wex
			`,
			shouldErr: false,
			expected:  httpHeaders{Added: nil, Removed: []string{"qas", "wex"}},
		},
		{
			name: "add header block",
			input: `header {
				foo bar
			}`,
			shouldErr: false,
			expected:  httpHeaders{Added: map[string]string{"foo": "bar"}, Removed: nil},
		},
		{
			name: "remove header block",
			input: `header {
				-baz
			}`,
			shouldErr: false,
			expected:  httpHeaders{Added: nil, Removed: []string{"baz"}},
		},
		{
			name: "add headers block",
			input: `header {
				foo bar
				spam eggs
			}`,
			shouldErr: false,
			expected:  httpHeaders{Added: map[string]string{"foo": "bar", "spam": "eggs"}, Removed: nil},
		},
		{
			name: "remove headers block",
			input: `header {
				-qas
				-wex
			}`,
			shouldErr: false,
			expected:  httpHeaders{Added: nil, Removed: []string{"qas", "wex"}},
		},
		{
			name: "add and remove headers mixed",
			input: `header {
				-wex
				foo bar

			}
			header spam eggs
			header -qas`,
			shouldErr: false,
			expected:  httpHeaders{Added: map[string]string{"foo": "bar", "spam": "eggs"}, Removed: []string{"wex", "qas"}},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		httpHeaders := httpHeaders{}
		err := httpHeaders.unmarshalHeaders(d)

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if !reflect.DeepEqual(test.expected.Added, httpHeaders.Added) {
				t.Errorf("Test %v (%v) %v: Created Headers (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, httpHeaders.Added, test.expected.Added)
			} else if !reflect.DeepEqual(test.expected.Removed, httpHeaders.Removed) {
				t.Errorf("Test %v (%v) %v: Created Headers (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, httpHeaders.Removed, test.expected.Removed)
			}
		}
	}
}
