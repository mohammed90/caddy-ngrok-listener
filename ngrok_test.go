package ngroklistener

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseNgrok(t *testing.T) {
	class := "ParseNgrok"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  Ngrok
	}{
		{
			name: "default",
			input: `ngrok {
			}`,
			shouldErr: false,
			expected:  Ngrok{},
		},
		{
			name: "set authtoken",
			input: `ngrok {
				authtoken test
			}`,
			shouldErr: false,
			expected:  Ngrok{AuthToken: "test"},
		},
		{
			name: "misc opts",
			input: `ngrok {
				region us
				server test.ngrok.com
				heartbeat_tolerance 1m
				heartbeat_interval 5s
			}`,
			shouldErr: false,
			expected:  Ngrok{Region: "us", Server: "test", HeartbeatTolerance: caddy.Duration(1 * time.Minute), HeartbeatInterval: caddy.Duration(5 * time.Second)},
		},
		{
			name: "load tcp",
			input: `ngrok {
				authtoken test
				tunnel tcp {

				}
			}`,
			shouldErr: false,
			expected:  Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"tcp"}`)},
		},
		{
			name: "load tls",
			input: `ngrok {
				authtoken test
				tunnel tls {

				}
			}`,
			shouldErr: false,
			expected:  Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"tls"}`)},
		},
		{
			name: "load http",
			input: `ngrok {
				authtoken test
				tunnel http {

				}
			}`, shouldErr: false,
			expected: Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"http"}`)},
		},
		{
			name: "load labeled",
			input: `ngrok {
				authtoken test
				tunnel labeled {

				}
			}`, shouldErr: false,
			expected: Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"labeled"}`)},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		n := Ngrok{}
		err := n.UnmarshalCaddyfile(d)

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.AuthToken != n.AuthToken {
				t.Errorf("Test %v (%v) %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, n.AuthToken, test.expected.AuthToken)
			} else if !reflect.DeepEqual(test.expected.TunnelRaw, n.TunnelRaw) {
				t.Errorf("Test %v (%v) %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, string(n.TunnelRaw), string(test.expected.TunnelRaw))
			}
		}
	}
}

func TestNgrokMetadata(t *testing.T) {
	class := "NgrokMetadata"

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expected  Ngrok
	}{
		{
			name: "absent",
			input: `ngrok {
			}`,
			shouldErr: false,
			expected:  Ngrok{Metadata: ""},
		},
		{
			name: "with metadata",
			input: `ngrok {
				metadata test
			}`,
			shouldErr: false,
			expected:  Ngrok{Metadata: "test"},
		},
		{
			name: "metadata-single-arg-quotes",
			input: `ngrok {
				metadata "Hello, World!"
			}`,
			shouldErr: false,
			expected:  Ngrok{Metadata: "Hello, World!"},
		},
		{
			name: "metadata-no-args",
			input: `ngrok {
				metadata
			}`,
			shouldErr: true,
			expected:  Ngrok{Metadata: ""},
		},
		{
			name: "metadata-too-many-args",
			input: `ngrok {
				metadata test test2
			}`,
			shouldErr: true,
			expected:  Ngrok{Metadata: ""},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		n := Ngrok{}
		err := n.UnmarshalCaddyfile(d)

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v (%v) %v: Expected error but found nil", class, i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v (%v) %v: Expected no error but found error: %v", class, i, test.name, err)
			} else if test.expected.Metadata != n.Metadata {
				t.Errorf("Test %v (%v) %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", class, i, test.name, n.Metadata, test.expected.Metadata)
			}
		}
	}
}
