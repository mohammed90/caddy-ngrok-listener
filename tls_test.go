package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestParseTLS(t *testing.T) {
	cases := genericTestCases[*TLS]{
		{
			name: "default",
			caddyInput: `tls {
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.NotNil(t, actual)
			},
			expectedOpts: config.TLSEndpoint(),
		},
	}

	cases.runAll(t)

}

func TestTLSDomain(t *testing.T) {
	cases := genericTestCases[*TLS]{
		{
			name: "absent",
			caddyInput: `tls {
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Empty(t, actual.Domain)
			},
			expectedOpts: config.TLSEndpoint(),
		},
		{
			name: "with domain",
			caddyInput: `tls {
				domain foo.ngrok.io
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Equal(t, actual.Domain, "foo.ngrok.io")
			},
			expectedOpts: config.TLSEndpoint(
				config.WithDomain("foo.ngrok.io"),
			),
		},
		{
			name: "domain-no-args",
			caddyInput: `tls {
				domain
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "domain-too-many-args",
			caddyInput: `tls {
				domain foo.ngrok.io foo.ngrok.io
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestTLSMetadata(t *testing.T) {
	cases := genericTestCases[*TLS]{
		{
			name: "absent",
			caddyInput: `tls {
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Empty(t, actual.Metadata)
			},
			expectedOpts: config.TLSEndpoint(),
		},
		{
			name: "with metadata",
			caddyInput: `tls {
				metadata test
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Equal(t, actual.Metadata, "test")
			},
			expectedOpts: config.TLSEndpoint(
				config.WithMetadata("test"),
			),
		},
		{
			name: "metadata-single-arg-quotes",
			caddyInput: `tls {
				metadata "Hello, World!"
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Equal(t, actual.Metadata, "Hello, World!")
			},
			expectedOpts: config.TLSEndpoint(
				config.WithMetadata("Hello, World!"),
			),
		},
		{
			name: "metadata-no-args",
			caddyInput: `tls {
				metadata
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "metadata-too-many-args",
			caddyInput: `tls {
				metadata test test2
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestTLSCIDRRestrictions(t *testing.T) {
	cases := genericTestCases[*TLS]{
		{
			name: "absent",
			caddyInput: `tls {
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Empty(t, actual.AllowCIDR)
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TLSEndpoint(),
		},
		{
			name: "allow",
			caddyInput: `tls {
				allow 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TLSEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8"),
			),
		},
		{
			name: "deny",
			caddyInput: `tls {
				deny 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8"})
			},
			expectedOpts: config.TLSEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8"),
			),
		},
		{
			name: "allow multi",
			caddyInput: `tls {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TLSEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "allow multi inline",
			caddyInput: `tls {
				allow 127.0.0.0/8 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TLSEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "deny multi",
			caddyInput: `tls {
				deny 127.0.0.0/8
				deny 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
			},
			expectedOpts: config.TLSEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "deny multi inline",
			caddyInput: `tls {
				deny 127.0.0.0/8 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
			},
			expectedOpts: config.TLSEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "allow and deny multi",
			caddyInput: `tls {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
				deny 192.0.0.0/8
				deny 172.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TLS) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.ElementsMatch(t, actual.DenyCIDR, []string{"192.0.0.0/8", "172.0.0.0/8"})
			},
			expectedOpts: config.TLSEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
				config.WithDenyCIDRString("192.0.0.0/8", "172.0.0.0/8"),
			),
		},
		{
			name: "allow-no-args",
			caddyInput: `tls {
				allow
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "deny-no-args",
			caddyInput: `tls {
				deny
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
