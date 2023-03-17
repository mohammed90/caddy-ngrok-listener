package ngroklistener

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

func TestParseNgrok(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
		{
			name: "default",
			caddyInput: `ngrok {
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.NotNil(t, actual)
				require.Empty(t, actual.AuthToken, "")
			},
		},
		{
			name: "set authtoken",
			caddyInput: `ngrok {
				authtoken test
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.AuthToken, "test")
			},
		},
		{
			name: "misc opts",
			caddyInput: `ngrok {
				region us
				server test.ngrok.com
				heartbeat_tolerance 1m
				heartbeat_interval 5s
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.Region, "us")
				require.Equal(t, actual.Server, "test.ngrok.com")
				require.Equal(t, actual.HeartbeatTolerance, caddy.Duration(1*time.Minute))
				require.Equal(t, actual.HeartbeatInterval, caddy.Duration(5*time.Second))
			},
		},
		{
			name: "load tunnel default",
			caddyInput: `ngrok {
				tunnel {

				}
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.TunnelRaw, json.RawMessage(`{"type":"tcp"}`))
			},
		},
		{
			name: "load tcp",
			caddyInput: `ngrok {
				tunnel tcp {

				}
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				j, err := actual.TunnelRaw.MarshalJSON()
				require.Nil(t, err)
				require.JSONEq(t, string(j), `{"type":"tcp"}`)
			},
		},
		{
			name: "load tls",
			caddyInput: `ngrok {
				tunnel tls {

				}
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				j, err := actual.TunnelRaw.MarshalJSON()
				require.Nil(t, err)
				require.JSONEq(t, string(j), `{"type":"tls"}`)
			},
		},
		{
			name: "load http",
			caddyInput: `ngrok {
				tunnel http {

				}
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				j, err := actual.TunnelRaw.MarshalJSON()
				require.Nil(t, err)
				require.JSONEq(t, string(j), `{"type":"http"}`)
			},
			// expected: Ngrok{AuthToken: "test", TunnelRaw: json.RawMessage(`{"type":"http"}`)},
		},
		{
			name: "load labeled",
			caddyInput: `ngrok {
				authtoken test
				tunnel labeled {
					label foo bar
				}
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				j, err := actual.TunnelRaw.MarshalJSON()
				require.Nil(t, err)
				require.JSONEq(t, string(j), `{"type":"labeled","labels":{"foo":"bar"}}`)
			},
		},
	}

	cases.runAll(t)

}

func TestNgrokMetadata(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
		{
			name: "absent",
			caddyInput: `ngrok {
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Empty(t, actual.Metadata)
			},
		},
		{
			name: "with metadata",
			caddyInput: `ngrok {
				metadata test
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.Metadata, "test")
			},
		},
		{
			name: "metadata-single-arg-quotes",
			caddyInput: `ngrok {
				metadata "Hello, World!"
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.Metadata, "Hello, World!")
			},
		},
		{
			name: "metadata-no-args",
			caddyInput: `ngrok {
				metadata
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "metadata-too-many-args",
			caddyInput: `ngrok {
				metadata test test2
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
