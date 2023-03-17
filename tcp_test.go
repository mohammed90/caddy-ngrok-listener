package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestParseTCP(t *testing.T) {
	cases := genericTestCases[*TCP]{
		{
			name: "default",
			caddyInput: `tcp {
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.NotNil(t, actual)
			},
			expectedOpts: config.TCPEndpoint(),
		},
		{
			name: "tcp takes no args",
			caddyInput: `tcp arg1 {
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "tcp unsupported directive",
			caddyInput: `tcp {
				directive
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestTCPRemoteAddr(t *testing.T) {
	cases := genericTestCases[*TCP]{
		{
			name: "remote addr",
			caddyInput: `tcp {
				remote_addr 0.tcp.ngrok.io:1234
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Equal(t, actual.RemoteAddr, "0.tcp.ngrok.io:1234")
			},
			expectedOpts: config.TCPEndpoint(
				config.WithRemoteAddr("0.tcp.ngrok.io:1234"),
			),
		},
		{
			name: "remote addr no arg",
			caddyInput: `tcp {
				remote_addr
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "remote addr extra args",
			caddyInput: `tcp {
				remote_addr 0.tcp.ngrok.io:1234 1.tcp.ngrok.io:1234
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestTCPMetadata(t *testing.T) {
	cases := genericTestCases[*TCP]{
		{
			name: "absent",
			caddyInput: `tcp {
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Empty(t, actual.Metadata)
			},
			expectedOpts: config.TCPEndpoint(),
		},
		{
			name: "with metadata",
			caddyInput: `tcp {
				metadata test
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Equal(t, actual.Metadata, "test")
			},
			expectedOpts: config.TCPEndpoint(
				config.WithMetadata("test"),
			),
		},
		{
			name: "metadata-single-arg-quotes",
			caddyInput: `tcp {
				metadata "Hello, World!"
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Equal(t, actual.Metadata, "Hello, World!")
			},
			expectedOpts: config.TCPEndpoint(
				config.WithMetadata("Hello, World!"),
			),
		},
		{
			name: "metadata-no-args",
			caddyInput: `tcp {
				metadata
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "metadata-too-many-args",
			caddyInput: `tcp {
				metadata test test2
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestTCPCIDRRestrictions(t *testing.T) {
	cases := genericTestCases[*TCP]{
		{
			name: "absent",
			caddyInput: `tcp {
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Empty(t, actual.AllowCIDR)
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TCPEndpoint(),
		},
		{
			name: "allow",
			caddyInput: `tcp {
				allow 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TCPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8"),
			),
		},
		{
			name: "deny",
			caddyInput: `tcp {
				deny 127.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8"})
			},
			expectedOpts: config.TCPEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8"),
			),
		},
		{
			name: "allow multi",
			caddyInput: `tcp {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TCPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "allow multi inline",
			caddyInput: `tcp {
				allow 127.0.0.0/8 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.Empty(t, actual.DenyCIDR)
			},
			expectedOpts: config.TCPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "deny multi",
			caddyInput: `tcp {
				deny 127.0.0.0/8
				deny 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
			},
			expectedOpts: config.TCPEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "deny multi inline",
			caddyInput: `tcp {
				deny 127.0.0.0/8 10.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.Empty(t, actual.AllowCIDR)
				require.ElementsMatch(t, actual.DenyCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
			},
			expectedOpts: config.TCPEndpoint(
				config.WithDenyCIDRString("127.0.0.0/8", "10.0.0.0/8"),
			),
		},
		{
			name: "allow and deny multi",
			caddyInput: `tcp {
				allow 127.0.0.0/8
				allow 10.0.0.0/8
				deny 192.0.0.0/8
				deny 172.0.0.0/8
			}`,
			expectConfig: func(t *testing.T, actual *TCP) {
				require.ElementsMatch(t, actual.AllowCIDR, []string{"127.0.0.0/8", "10.0.0.0/8"})
				require.ElementsMatch(t, actual.DenyCIDR, []string{"192.0.0.0/8", "172.0.0.0/8"})
			},
			expectedOpts: config.TCPEndpoint(
				config.WithAllowCIDRString("127.0.0.0/8", "10.0.0.0/8"),
				config.WithDenyCIDRString("192.0.0.0/8", "172.0.0.0/8"),
			),
		},
		{
			name: "allow-no-args",
			caddyInput: `tcp {
				allow
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "deny-no-args",
			caddyInput: `tcp {
				deny
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
