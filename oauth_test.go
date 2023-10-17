package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestOAuth(t *testing.T) {
	cases := genericNgrokTestCases[*oauth]{
		{
			name:               "absent",
			caddyInput:         `{}`,
			expectUnmarshalErr: true,
		},
		{
			name: "simple",
			caddyInput: `{
				provider google
			}`,
			expectConfig: func(t *testing.T, actual *oauth) {
				require.Equal(t, actual.Provider, "google")
			},
			expectedOptsFunc: func(t *testing.T, actual *oauth) {
				require.NotNil(t, actual.opt)
				require.Equal(t,
					config.HTTPEndpoint(actual.opt),
					config.HTTPEndpoint(config.WithOAuth("google")),
				)
			},
		},
		{
			name: "with options",
			caddyInput: `{
				provider google
				scopes foo
				scopes bar baz
				allow_domains ngrok.com google.com
				allow_domains github.com facebook.com
				allow_emails user1@gmail.com user2@gmail.com
				allow_emails user3@gmail.com
			}`,
			expectConfig: func(t *testing.T, actual *oauth) {
				require.Equal(t, actual.Provider, "google")
				require.ElementsMatch(t, actual.Scopes, []string{"foo", "bar", "baz"})
				require.ElementsMatch(t, actual.AllowDomains, []string{"ngrok.com", "google.com", "github.com", "facebook.com"})
				require.ElementsMatch(t, actual.AllowEmails, []string{"user1@gmail.com", "user2@gmail.com", "user3@gmail.com"})
			},
			expectedOptsFunc: func(t *testing.T, actual *oauth) {
				require.NotNil(t, actual.opt)
				require.Equal(t,
					config.HTTPEndpoint(actual.opt),
					config.HTTPEndpoint(
						config.WithOAuth("google",
							config.WithAllowOAuthDomain("ngrok.com", "google.com", "github.com", "facebook.com"),
							config.WithAllowOAuthEmail("user1@gmail.com", "user2@gmail.com", "user3@gmail.com"),
							config.WithOAuthScope("foo", "bar", "baz"),
						),
					),
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
