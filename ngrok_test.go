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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			n := Ngrok{}
			err := n.UnmarshalCaddyfile(d)

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected error but found nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but found error: %v", err)
				} else if test.expected.AuthToken != n.AuthToken {
					t.Errorf("Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", n.AuthToken, test.expected.AuthToken)
				} else if !reflect.DeepEqual(test.expected.TunnelRaw, n.TunnelRaw) {
					t.Errorf("Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", string(n.TunnelRaw), string(test.expected.TunnelRaw))
				}
			}
		})
	}
}

func TestNgrokMetadata(t *testing.T) {
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(test.input)
			n := Ngrok{}
			err := n.UnmarshalCaddyfile(d)

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected error but found nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but found error: %v", err)
				} else if test.expected.Metadata != n.Metadata {
					t.Errorf("Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", n.Metadata, test.expected.Metadata)
				}
			}
		})
	}
}
