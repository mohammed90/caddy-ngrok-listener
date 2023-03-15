package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestOIDC(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name:               "absent",
			caddyInput:         `{}`,
			expectUnmarshalErr: true,
		},
		{
			name: "simple",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				client_secret bar
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Equal(t, actual.IssuerURL, "https://google.com")
				require.Equal(t, actual.ClientID, "foo")
				require.Equal(t, actual.ClientSecret, "bar")
			},
			expectedOptsFunc: func(t *testing.T, actual *oidc) {
				require.NotNil(t, actual.OIDCOption)
				require.Equal(t,
					config.HTTPEndpoint(actual.OIDCOption),
					config.HTTPEndpoint(config.WithOIDC("https://google.com", "foo", "bar")),
				)
			},
		},
		{
			name: "with options",
			caddyInput: `{
				issuer_url google
				client_id foo
				client_secret bar
				scopes foo
				scopes bar baz
				allow_domains ngrok.com google.com
				allow_domains github.com
				allow_emails user1@gmail.com user2@gmail.com
				allow_emails user3@gmail.com
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Equal(t, actual.IssuerURL, "google")
				require.Equal(t, actual.ClientID, "foo")
				require.Equal(t, actual.ClientSecret, "bar")
				require.ElementsMatch(t, actual.Scopes, []string{"foo", "bar", "baz"})
				require.ElementsMatch(t, actual.AllowDomains, []string{"ngrok.com", "google.com", "github.com"})
				require.ElementsMatch(t, actual.AllowEmails, []string{"user1@gmail.com", "user2@gmail.com", "user3@gmail.com"})
			},
			expectedOptsFunc: func(t *testing.T, actual *oidc) {
				require.NotNil(t, actual.OIDCOption)
				require.Equal(t,
					config.HTTPEndpoint(actual.OIDCOption),
					config.HTTPEndpoint(config.WithOIDC(
						"google",
						"foo",
						"bar",
						config.WithAllowOIDCDomain("ngrok.com", "google.com", "github.com"),
						config.WithAllowOIDCEmail("user1@gmail.com", "user2@gmail.com", "user3@gmail.com"),
						config.WithOIDCScope("foo", "bar", "baz"),
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

func TestOIDCIssuerUrl(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name: "empty-issuer-url",
			caddyInput: `{
				client_id foo
				client_secret bar
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Empty(t, actual.IssuerURL)
				require.Equal(t, actual.ClientID, "foo")
				require.Equal(t, actual.ClientSecret, "bar")
			},
			expectProvisionErr: true,
		},
		{
			name: "no-args",
			caddyInput: `{
				issuer_url
				client_id foo
				client_secret bar
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "too-many-args",
			caddyInput: `{
				issuer_url https://google.com https://google2.com
				client_id foo
				client_secret bar
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
func TestOIDCClientID(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name: "empty-client-id",
			caddyInput: `{
				issuer_url https://google.com
				client_secret bar
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Equal(t, actual.IssuerURL, "https://google.com")
				require.Empty(t, actual.ClientID)
				require.Equal(t, actual.ClientSecret, "bar")
			},
			expectProvisionErr: true,
		},
		{
			name: "no-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id
				client_secret bar
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "too-many-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo baz
				client_secret bar
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestOIDCClientSecret(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name: "empty-client-secret",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Equal(t, actual.IssuerURL, "https://google.com")
				require.Equal(t, actual.ClientID, "foo")
				require.Empty(t, actual.ClientSecret)
			},
			expectProvisionErr: true,
		},
		{
			name: "no-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				client_secret
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "too-many-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				client_secret bar baz
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestOIDCScopes(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name: "empty",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				client_secret bar
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Nil(t, actual.Scopes)
			},
			expectedOptsFunc: func(t *testing.T, actual *oidc) {
				require.NotNil(t, actual.OIDCOption)
				require.Equal(t,
					config.HTTPEndpoint(actual.OIDCOption),
					config.HTTPEndpoint(config.WithOIDC(
						"https://google.com",
						"foo",
						"bar",
					),
					),
				)
			},
		},
		{
			name: "no-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				scopes
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestOIDCAllowDomains(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name: "empty",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				client_secret bar
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Nil(t, actual.AllowDomains)
			},
			expectedOptsFunc: func(t *testing.T, actual *oidc) {
				require.NotNil(t, actual.OIDCOption)
				require.Equal(t,
					config.HTTPEndpoint(actual.OIDCOption),
					config.HTTPEndpoint(config.WithOIDC(
						"https://google.com",
						"foo",
						"bar",
					),
					),
				)
			},
		},
		{
			name: "no-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				allow_domains
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestOIDCAllowEmails(t *testing.T) {
	cases := genericNgrokTestCases[*oidc]{
		{
			name: "empty",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				client_secret bar
			}`,
			expectConfig: func(t *testing.T, actual *oidc) {
				require.Nil(t, actual.AllowEmails)
			},
			expectedOptsFunc: func(t *testing.T, actual *oidc) {
				require.NotNil(t, actual.OIDCOption)
				require.Equal(t,
					config.HTTPEndpoint(actual.OIDCOption),
					config.HTTPEndpoint(config.WithOIDC(
						"https://google.com",
						"foo",
						"bar",
					),
					),
				)
			},
		},
		{
			name: "no-args",
			caddyInput: `{
				issuer_url https://google.com
				client_id foo
				allow_emails
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
