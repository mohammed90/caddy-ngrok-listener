package ngroklistener

import (
	"time"
	// "reflect"
	"encoding/json"
	"reflect"
	"testing"

	// "github.com/caddyserver/caddy/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseNgrok(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  Ngrok
	}{
		{`ngrok {
			metadata test
		}`, false, Ngrok{Metadata: "test"}},
		{`ngrok {
			authtoken test
		}`, false, Ngrok{AuthToken: "test"}},
		{`ngrok {
			region us
			server test.ngrok.com
			heartbeat_tolerance 1m
			heartbeat_interval 5s
		}`, false, Ngrok{Region: "us", Server: "test", HeartbeatTolerance: caddy.Duration(1 * time.Minute), HeartbeatInterval: caddy.Duration(5 * time.Second)}},
		{`ngrok {
			authtoken test
			tunnel tcp {

			}
		}`, false, Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"tcp"}`)}},
		{`ngrok {
			authtoken test
			tunnel tls {

			}
		}`, false, Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"tls"}`)}},
		{`ngrok {
			authtoken test
			tunnel http {

			}
		}`, false, Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"http"}`)}},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		n := Ngrok{}
		err := n.UnmarshalCaddyfile(d)

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v: Expected error but found nil", i)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v: Expected no error but found error: %v", i, err)
			} else if test.expected.Metadata != n.Metadata {
				t.Errorf("Test %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", i, n.Metadata, test.expected.Metadata)
			} else if test.expected.AuthToken != n.AuthToken {
				t.Errorf("Test %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", i, n.AuthToken, test.expected.AuthToken)
			} else if !reflect.DeepEqual(test.expected.TunnelRaw, n.TunnelRaw) {
				t.Errorf("Test %v: Created Ngrok (\n%#v\n) does not match expected (\n%#v\n)", i, string(n.TunnelRaw), string(test.expected.TunnelRaw))
			}
		}
	}
}
