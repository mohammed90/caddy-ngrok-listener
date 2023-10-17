package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestWebhookVerification(t *testing.T) {
	cases := genericNgrokTestCases[*webhookVerification]{
		{
			name:               "absent",
			caddyInput:         `{}`,
			expectUnmarshalErr: true,
		},
		{
			name: "single",
			caddyInput: `{
				provider google
				secret domoarigato
			}`,
			expectConfig: func(t *testing.T, actual *webhookVerification) {
				require.Equal(t, actual.Provider, "google")
				require.Equal(t, actual.Secret, "domoarigato")
			},
			expectedOptsFunc: func(t *testing.T, actual *webhookVerification) {
				require.NotNil(t, actual.opt)
				require.Equal(t,
					config.HTTPEndpoint(actual.opt),
					config.HTTPEndpoint(config.WithWebhookVerification("google", "domoarigato")),
				)
			},
		},
		{
			name: "unsupported directive",
			caddyInput: `{
				directive
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestWebhookVerificationProvider(t *testing.T) {
	cases := genericNgrokTestCases[*webhookVerification]{
		{
			name: "empty-provider",
			caddyInput: `{
				secret foo
			}`,
			expectConfig: func(t *testing.T, actual *webhookVerification) {
				require.Empty(t, actual.Provider)
				require.Equal(t, actual.Secret, "foo")
			},
			expectProvisionErr: true,
		},
		{
			name: "no-args",
			caddyInput: `{
				provider
				secret foo
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "too-many-args",
			caddyInput: `{
				provider google gitlab
				secret foo
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestWebhookVerificationSecret(t *testing.T) {
	cases := genericNgrokTestCases[*webhookVerification]{
		{
			name: "empty-secret",
			caddyInput: `{
				provider google
			}`,
			expectConfig: func(t *testing.T, actual *webhookVerification) {
				require.Equal(t, actual.Provider, "google")
				require.Empty(t, actual.Secret)
			},
			expectProvisionErr: true,
		},
		{
			name: "no-args",
			caddyInput: `{
				provider google
				secret
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "too-many-args",
			caddyInput: `{
				provider google
				secret foo bar
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
