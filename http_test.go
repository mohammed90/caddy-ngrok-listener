package ngroklistener

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestParseHTTP(t *testing.T) {
	cases := genericTestCases[*HTTP]{

		{
			name: "default",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.NotNil(t, actual)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "http takes no args",
			caddyInput: `http arg1 {
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "http unsupported directive",
			caddyInput: `http {
				directive
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPBasicAuth(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "empty",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Nil(t, actual.BasicAuth)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "single-inline",
			caddyInput: `http {
				basic_auth foo barbarbar
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				expected := []basicAuthCred{
					{"foo", "barbarbar"},
				}

				require.Equal(t, expected, actual.BasicAuth)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithBasicAuth("foo", "barbarbar"),
			),
		},
		{
			name: "single-block",
			caddyInput: `http {
				basic_auth {
					foo barbarbar
				}
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				expected := []basicAuthCred{
					{"foo", "barbarbar"},
				}

				require.Equal(t, expected, actual.BasicAuth)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithBasicAuth("foo", "barbarbar"),
			),
		},
		{
			name: "multiple",
			caddyInput: `http {
				basic_auth foo barbarbar
				basic_auth spam eggsandcheese
				basic_auth {
					bar bazbazbaz
					bam bambinos
				}
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				expected := []basicAuthCred{
					{"foo", "barbarbar"},
					{"spam", "eggsandcheese"},
					{"bar", "bazbazbaz"},
					{"bam", "bambinos"},
				}

				require.Equal(t, expected, actual.BasicAuth)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithBasicAuth("foo", "barbarbar"),
				config.WithBasicAuth("spam", "eggsandcheese"),
				config.WithBasicAuth("bar", "bazbazbaz"),
				config.WithBasicAuth("bam", "bambinos"),
			),
		},
		{
			name: "inline-password-too-short",
			caddyInput: `http {
				basic_auth foo bar
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "block-password-too-short",
			caddyInput: `http {
				basic_auth {
					foo bar
				}
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-inline-no-arg",
			caddyInput: `http {
				basic_auth
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-inline-no-password",
			caddyInput: `http {
				basic_auth foo
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-inline-too-many-arg",
			caddyInput: `http {
				basic_auth foo barbarbar bazbazbaz
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-block-no-arg",
			caddyInput: `http {
				basic_auth {

				}
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-block-no-password",
			caddyInput: `http {
				basic_auth {
					foo
				}
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-block-too-many-arg",
			caddyInput: `http {
				basic_auth {
					foo barbarbar bazbazbaz
				}
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "basic_auth-no-combine",
			caddyInput: `http {
				basic_auth foo barbarbar {
					spam eggsandcheese
				}
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPCircuitBreaker(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "absent",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Zero(t, actual.Options["circuit_breaker"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithCircuitBreaker(0),
			),
		},
		{
			name: "breakered",
			caddyInput: `http {
				circuit_breaker 0.5
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, caddy.ModuleMap{"circuit_breaker": json.RawMessage(`0.5`)}, actual.Options)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithCircuitBreaker(0.5),
			),
		},
		{
			name: "breakered-no-arg",
			caddyInput: `http {
				circuit_breaker
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "set unrecognized",
			caddyInput: `http {
				circuit_breaker foo
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "breakered-too-many-arg",
			caddyInput: `http {
				circuit_breaker 0.3 0.7
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPCompression(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "absent",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Zero(t, actual.Options["compression"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "compressed-off",
			caddyInput: `http {
				compression off
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`false`), actual.Options["compression"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "compressed-false",
			caddyInput: `http {
				compression false
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`false`), actual.Options["compression"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "compressed-true",
			caddyInput: `http {
				compression true
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`true`), actual.Options["compression"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithCompression(),
			),
		},
		{
			name: "compressed-no-arg",
			caddyInput: `http {
				compression
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`true`), actual.Options["compression"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithCompression(),
			),
		},
		{
			name: "set unrecognized",
			caddyInput: `http {
				compression foo
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "compressed-too-many-arg",
			caddyInput: `http {
				compression true false
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPWebsocketTCPConversion(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "absent",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Zero(t, actual.Options["websocket_tcp_conversion"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "converted-off",
			caddyInput: `http {
				websocket_tcp_conversion off
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`false`), actual.Options["websocket_tcp_conversion"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "converted-false",
			caddyInput: `http {
				websocket_tcp_conversion false
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`false`), actual.Options["websocket_tcp_conversion"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "converted-true",
			caddyInput: `http {
				websocket_tcp_conversion true
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`true`), actual.Options["websocket_tcp_conversion"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithWebsocketTCPConversion(),
			),
		},
		{
			name: "converted-no-arg",
			caddyInput: `http {
				websocket_tcp_conversion
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`true`), actual.Options["websocket_tcp_conversion"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithWebsocketTCPConversion(),
			),
		},
		{
			name: "set unrecognized",
			caddyInput: `http {
				websocket_tcp_conversion foo
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "converted-too-many-arg",
			caddyInput: `http {
				websocket_tcp_conversion true false
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPDomain(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "absent",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["domain"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "with domain",
			caddyInput: `http {
				domain foo.ngrok.io
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`"foo.ngrok.io"`), actual.Options["domain"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithDomain("foo.ngrok.io"),
			),
		},
		{
			name: "domain-no-args",
			caddyInput: `http {
				domain
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "domain-too-many-args",
			caddyInput: `http {
				domain foo.ngrok.io test.ngrok.io
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPMetadata(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "absent",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["metadata"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "with metadata",
			caddyInput: `http {
				metadata test
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(quoteString("test")), actual.Options["metadata"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithMetadata("test"),
			),
		},
		{
			name: "metadata-single-arg-quotes",
			caddyInput: `http {
				metadata "Hello, World!"
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(quoteString("Hello, World!")), actual.Options["metadata"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithMetadata("Hello, World!"),
			),
		},
		{
			name: "metadata-no-args",
			caddyInput: `http {
				metadata
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "metadata-too-many-args",
			caddyInput: `http {
				metadata test test2
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPScheme(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "default",
			caddyInput: `http {
			}`,
			expectUnmarshalErr: false,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["scheme"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "set https",
			caddyInput: `http {
				scheme https
			}`,
			expectUnmarshalErr: false,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`"https"`), actual.Options["scheme"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithScheme("https"),
			),
		},
		{
			name: "set http",
			caddyInput: `http {
				scheme http
			}`,
			expectUnmarshalErr: false,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`"http"`), actual.Options["scheme"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithScheme("http"),
			),
		},
		{
			name: "set unrecognized",
			caddyInput: `http {
				scheme foo
			}`,
			expectUnmarshalErr: false,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, json.RawMessage(`"foo"`), actual.Options["scheme"])
			},
			expectProvisionErr: true,
		},
		{
			name: "scheme-no-arg",
			caddyInput: `http {
				scheme
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "scheme-too-many-arg",
			caddyInput: `http {
				scheme http https
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestHTTPCIDRRestrictions(t *testing.T) {
	cases := genericTestCases[*HTTP]{
		{
			name: "absent",
			caddyInput: `http {
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["allow_cidr"])
				require.Empty(t, actual.Options["deny_cidr"])
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "allow",
			caddyInput: `http {
				allow 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.JSONEq(t, `["127.0.0.0/8"]`, string(actual.Options["allow_cidr"]))
				require.Empty(t, actual.Options["deny_cidr"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8"),
			),
		},
		{
			name: "deny",
			caddyInput: `http {
				deny 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["allow_cidr"])
				require.JSONEq(t, `["127.0.0.0/8"]`, string(actual.Options["deny_cidr"]))
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8"),
			),
		},
		{
			name: "allow multi",
			caddyInput: `http {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.JSONEq(t, `["127.0.0.0/8", "10.0.0.0/8"]`, string(actual.Options["allow_cidr"]))
				require.Empty(t, actual.Options["deny_cidr"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "allow multi inline",
			caddyInput: `http {
				allow 127.0.0.0/8 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.JSONEq(t, `["127.0.0.0/8", "10.0.0.0/8"]`, string(actual.Options["allow_cidr"]))
				require.Empty(t, actual.Options["deny_cidr"])
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "deny multi",
			caddyInput: `http {
				deny 127.0.0.0/8
				deny 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["allow_cidr"])
				require.JSONEq(t, `["127.0.0.0/8", "10.0.0.0/8"]`, string(actual.Options["deny_cidr"]))
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "deny multi inline",
			caddyInput: `http {
				deny 127.0.0.0/8 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Empty(t, actual.Options["allow_cidr"])
				require.JSONEq(t, `["127.0.0.0/8", "10.0.0.0/8"]`, string(actual.Options["deny_cidr"]))
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "allow and deny multi",
			caddyInput: `http {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
				deny 192.0.0.0/8
				deny 172.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.JSONEq(t, `["127.0.0.0/8", "10.0.0.0/8"]`, string(actual.Options["allow_cidr"]))
				require.JSONEq(t, `["192.0.0.0/8", "172.0.0.0/8"]`, string(actual.Options["deny_cidr"]))
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
				config.WithDenyCIDRString("192.0.0.0/8", "172.0.0.0/8"),
			),
		},
		{
			name: "allow-no-args",
			caddyInput: `http {
				allow
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "deny-no-args",
			caddyInput: `http {
				deny
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
