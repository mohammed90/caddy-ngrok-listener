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
			},
		},
		{
			name: "ngrok takes no args",
			caddyInput: `ngrok arg1 {
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "ngrok unsupported directive",
			caddyInput: `ngrok {
				directive
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestNgrokAuthToken(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
		{
			name: "empty",
			caddyInput: `ngrok {
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Empty(t, actual.AuthToken)
			},
		},
		{
			name: "set auth_token",
			caddyInput: `ngrok {
				auth_token foo
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.AuthToken, "foo")
			},
		},
		{
			name: "auth_token-no-arg",
			caddyInput: `ngrok {
				auth_token
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Empty(t, actual.AuthToken)
			},
		},
		{
			name: "auth_token-too-many-arg",
			caddyInput: `ngrok {
				auth_token foo bar
			}`,
			expectUnmarshalErr: true,
		},
	}
	cases.runAll(t)
}

func TestNgrokRegion(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
		{
			name: "empty",
			caddyInput: `ngrok {
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Empty(t, actual.Region)
			},
		},
		{
			name: "set region",
			caddyInput: `ngrok {
				region us
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.Region, "us")
			},
		},
		{
			name: "region-no-arg",
			caddyInput: `ngrok {
				region
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "region-too-many-arg",
			caddyInput: `ngrok {
				region foo bar
			}`,
			expectUnmarshalErr: true,
		},
	}
	cases.runAll(t)
}

func TestNgrokServer(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
		{
			name: "empty",
			caddyInput: `ngrok {
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Empty(t, actual.Server)
			},
		},
		{
			name: "set region",
			caddyInput: `ngrok {
				server test.ngrok.com
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.Server, "test.ngrok.com")
			},
		},
		{
			name: "server-no-arg",
			caddyInput: `ngrok {
				server
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "server-too-many-arg",
			caddyInput: `ngrok {
				server test.ngrok.com test2.ngrok.com
			}`,
			expectUnmarshalErr: true,
		},
	}
	cases.runAll(t)
}

func TestNgrokHeartbeat(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
		{
			name: "empty",
			caddyInput: `ngrok {
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Empty(t, actual.HeartbeatInterval)
				require.Empty(t, actual.HeartbeatTolerance)
			},
		},
		{
			name: "set heartbeat_interval",
			caddyInput: `ngrok {
				heartbeat_interval 5s
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.HeartbeatInterval, caddy.Duration(5*time.Second))
			},
		},
		{
			name: "set heartbeat_tolerance",
			caddyInput: `ngrok {
				heartbeat_tolerance 1m
			}`,
			expectConfig: func(t *testing.T, actual *Ngrok) {
				require.Equal(t, actual.HeartbeatTolerance, caddy.Duration(1*time.Minute))

			},
		},
		{
			name: "heartbeat-interval-no-arg",
			caddyInput: `ngrok {
				heartbeat_interval
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "heartbeat-tolerance-no-arg",
			caddyInput: `ngrok {
				heartbeat_tolerance
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "heartbeat-interval-too-many-arg",
			caddyInput: `ngrok {
				heartbeat_interval 1m 2m
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "heartbeat-tolerance-too-many-arg",
			caddyInput: `ngrok {
				heartbeat_tolerance 1m 2m
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "heartbeat-interval-parse-err",
			caddyInput: `ngrok {
				heartbeat_interval foo
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "heartbeat-tolerance-parse-err",
			caddyInput: `ngrok {
				heartbeat_tolerance foo
			}`,
			expectUnmarshalErr: true,
		},
	}
	cases.runAll(t)
}

func TestNgrokTunnel(t *testing.T) {
	cases := genericNgrokTestCases[*Ngrok]{
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
				auth_token test
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
		{
			name: "load tunnel extra args",
			caddyInput: `ngrok {
				tunnel tcp arg1 {

				}
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "load tunnel unrecognized type",
			caddyInput: `ngrok {
				tunnel foo{

				}
			}`,
			expectUnmarshalErr: true,
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
