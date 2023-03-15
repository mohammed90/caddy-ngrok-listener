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
			name: "",
			input: `ngrok {
				metadata test
			}`,
			shouldErr: false,
			expected:  Ngrok{Metadata: "test"},
		},
		{
			name: "",
			input: `ngrok {
				authtoken test
			}`,
			shouldErr: false,
			expected:  Ngrok{AuthToken: "test"},
		},
		{
			name: "",
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
			name: "",
			input: `ngrok {
				authtoken test
				tunnel tcp {

				}
			}`,
			shouldErr: false,
			expected:  Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"tcp"}`)},
		},
		{
			name: "",
			input: `ngrok {
				authtoken test
				tunnel tls {

				}
			}`,
			shouldErr: false,
			expected:  Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"tls"}`)},
		},
		{
			name: "",
			input: `ngrok {
				authtoken test
				tunnel http {

				}
			}`, shouldErr: false,
			expected: Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"http"}`)},
		},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		n := Ngrok{}
		err := n.UnmarshalCaddyfile(d)

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test (%v) %v: Expected error but found nil", i, test.name)
			}
		} else {
			if err != nil {
				t.Errorf("Test (%v) %v: Expected no error but found error: %v", i, test.name, err)
			} else if test.expected.Metadata != n.Metadata {
				t.Errorf("Test (%v) %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, n.Metadata, test.expected.Metadata)
			} else if test.expected.AuthToken != n.AuthToken {
				t.Errorf("Test (%v) %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, n.AuthToken, test.expected.AuthToken)
			} else if !reflect.DeepEqual(test.expected.TunnelRaw, n.TunnelRaw) {
				t.Errorf("Test (%v) %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", i, test.name, string(n.TunnelRaw), string(test.expected.TunnelRaw))
			}
		}
	}
}
