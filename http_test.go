package ngroklistener

import (
	"testing"

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
				require.Empty(t, actual.BasicAuth)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "single-inline",
			caddyInput: `http {
				basic_auth foo barbarbar
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.NotEmpty(t, actual.BasicAuth)
				require.Len(t, actual.BasicAuth, 1)
				require.Contains(t, actual.BasicAuth, "foo")
				require.Equal(t, actual.BasicAuth["foo"], "barbarbar")
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
				require.NotEmpty(t, actual.BasicAuth)
				require.Len(t, actual.BasicAuth, 1)
				require.Contains(t, actual.BasicAuth, "foo")
				require.Equal(t, actual.BasicAuth["foo"], "barbarbar")
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithBasicAuth("foo", "barbarbar"),
			),
		},
		// TODO: This test errors in the expectedOpts due to order of map not being consistent.
		// {
		// 	name: "multiple",
		// 	caddyInput: `http {
		// 		basic_auth foo barbarbar
		// 		basic_auth spam eggsandcheese
		// 		basic_auth {
		// 			bar bazbazbaz
		// 			bam bambinos
		// 		}
		// 	}`,
		// 	expectConfig: func(t *testing.T, actual *HTTP) {
		// 		require.NotEmpty(t, actual.BasicAuth)
		// 		require.Len(t, actual.BasicAuth, 4)
		// 		require.Contains(t, actual.BasicAuth, "foo")
		// 		require.Equal(t, actual.BasicAuth["foo"], "barbarbar")
		// 		require.Contains(t, actual.BasicAuth, "spam")
		// 		require.Equal(t, actual.BasicAuth["spam"], "eggsandcheese")
		// 		require.Contains(t, actual.BasicAuth, "bar")
		// 		require.Equal(t, actual.BasicAuth["bar"], "bazbazbaz")
		// 		require.Contains(t, actual.BasicAuth, "bam")
		// 		require.Equal(t, actual.BasicAuth["bam"], "bambinos")
		// 	},
		// 	expectedOpts: config.HTTPEndpoint(
		// 		config.WithBasicAuth("spam", "eggsandcheese"),
		// 		config.WithBasicAuth("bam", "bambinos"),
		// 		config.WithBasicAuth("bar", "bazbazbaz"),
		// 		config.WithBasicAuth("foo", "barbarbar"),
		// 	),
		// },
		{
			name: "password-too-short",
			caddyInput: `http {
				basic_auth foo bar
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
				require.Zero(t, actual.CircuitBreaker)
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
				require.Equal(t, actual.CircuitBreaker, 0.5)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithCircuitBreaker(0.5),
			),
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
				require.False(t, actual.Compression)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "compressed-off",
			caddyInput: `http {
				compression off
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.False(t, actual.Compression)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "compressed-false",
			caddyInput: `http {
				compression false
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.False(t, actual.Compression)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "compressed-true",
			caddyInput: `http {
				compression true
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.True(t, actual.Compression)
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
				require.True(t, actual.Compression)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithCompression(),
			),
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
				require.False(t, actual.WebsocketTCPConverter)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "converted-off",
			caddyInput: `http {
				websocket_tcp_converter off
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.False(t, actual.WebsocketTCPConverter)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "converted-false",
			caddyInput: `http {
				websocket_tcp_converter false
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.False(t, actual.WebsocketTCPConverter)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "converted-true",
			caddyInput: `http {
				websocket_tcp_converter true
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.True(t, actual.WebsocketTCPConverter)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithWebsocketTCPConversion(),
			),
		},
		{
			name: "converted-no-arg",
			caddyInput: `http {
				websocket_tcp_converter true
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.True(t, actual.WebsocketTCPConverter)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithWebsocketTCPConversion(),
			),
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
				require.Empty(t, actual.Domain)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "with domain",
			caddyInput: `http {
				domain foo.ngrok.io
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, actual.Domain, "foo.ngrok.io")
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
				require.Empty(t, actual.Metadata)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "with metadata",
			caddyInput: `http {
				metadata test
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.Equal(t, actual.Metadata, "test")
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
				require.Equal(t, actual.Metadata, "Hello, World!")
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
				require.Empty(t, actual.Scheme)
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
				require.Equal(t, "https", actual.Scheme)
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
				require.Equal(t, "http", actual.Scheme)
			},
			expectedOpts: config.HTTPEndpoint(
				config.WithScheme("http"),
			),
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
				require.Empty(t, actual.AllowCIDR)
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.HTTPEndpoint(),
		},
		{
			name: "allow",
			caddyInput: `http {
				allow 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *HTTP) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
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
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8"})
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
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
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
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
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
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
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
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
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
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.ElementsMatch(t, actual.DenyCIDR, []string{"192.0.0.0/8", "172.0.0.0/8"})
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
