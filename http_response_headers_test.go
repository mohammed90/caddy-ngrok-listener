package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestHTTPResponseHeaders(t *testing.T) {
	cases := genericNgrokTestCases[*httpResponseHeaders]{
		{
			name:       "absent",
			caddyInput: `{}`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.Nil(t, actual.opts)
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint()
			},
		},
		{
			name:       "add header inline",
			caddyInput: `header foo bar`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.Contains(t, actual.Added, "foo")
				require.Equal(t, actual.Added["foo"], "bar")
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithResponseHeader("foo", "bar"),
				)
			},
		},
		{
			name:       "remove header inline",
			caddyInput: `header -baz`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.ElementsMatch(t, actual.Removed, []string{"baz"})
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithRemoveResponseHeader("baz"),
				)
			},
		},
		{
			name: "add headers inline",
			caddyInput: `
				header foo bar
				header spam eggs
			`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.Contains(t, actual.Added, "foo")
				require.Equal(t, actual.Added["foo"], "bar")
				require.Contains(t, actual.Added, "spam")
				require.Equal(t, actual.Added["spam"], "eggs")
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithResponseHeader("foo", "bar"),
					config.WithResponseHeader("spam", "eggs"),
				)
			},
		},
		{
			name: "remove headers inline",
			caddyInput: `
				header -qas
				header -wex
			`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.ElementsMatch(t, actual.Removed, []string{"qas", "wex"})
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithRemoveResponseHeader("qas"),
					config.WithRemoveResponseHeader("wex"),
				)
			},
		},
		{
			name: "add header block",
			caddyInput: `header {
				foo bar
			}`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.Contains(t, actual.Added, "foo")
				require.Equal(t, actual.Added["foo"], "bar")
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithResponseHeader("foo", "bar"),
				)
			},
		},
		{
			name: "remove header block",
			caddyInput: `header {
				-baz
			}`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.ElementsMatch(t, actual.Removed, []string{"baz"})
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithRemoveResponseHeader("baz"),
				)
			},
		},
		{
			name: "add headers block",
			caddyInput: `header {
				foo bar
				spam eggs
			}`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.Contains(t, actual.Added, "foo")
				require.Equal(t, actual.Added["foo"], "bar")
				require.Contains(t, actual.Added, "spam")
				require.Equal(t, actual.Added["spam"], "eggs")
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithResponseHeader("foo", "bar"),
					config.WithResponseHeader("spam", "eggs"),
				)
			},
		},
		{
			name: "remove headers block",
			caddyInput: `header {
				-qas
				-wex
			}`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.ElementsMatch(t, actual.Removed, []string{"qas", "wex"})
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithRemoveResponseHeader("qas"),
					config.WithRemoveResponseHeader("wex"),
				)
			},
		},
		{
			name: "add and remove headers mixed",
			caddyInput: `header {
				-wex
				foo bar

			}
			header spam eggs
			header -qas`,
			expectConfig: func(t *testing.T, actual *httpResponseHeaders) {
				require.Contains(t, actual.Added, "foo")
				require.Equal(t, actual.Added["foo"], "bar")
				require.Contains(t, actual.Added, "spam")
				require.Equal(t, actual.Added["spam"], "eggs")
				require.ElementsMatch(t, actual.Removed, []string{"qas", "wex"})
			},
			expectedOptsFunc: func(t *testing.T, actual *httpResponseHeaders) {
				config.HTTPEndpoint(
					config.WithResponseHeader("foo", "bar"),
					config.WithResponseHeader("spam", "eggs"),
					config.WithRemoveResponseHeader("qas"),
					config.WithRemoveResponseHeader("wex"),
				)
			},
		},
	}

	cases.runAll(t)
}
