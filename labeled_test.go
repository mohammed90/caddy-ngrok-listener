package ngroklistener

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

func TestParseLabeled(t *testing.T) {
	cases := genericTestCases[*Labeled]{
		{
			name: "default",
			caddyInput: `labeled {
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.Empty(t, actual.Labels)
			},
			expectProvisionErr: true,
		},
		{
			name: "simple-inline",
			caddyInput: `labeled {
				label foo bar
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.NotEmpty(t, actual.Labels)
				require.Len(t, actual.Labels, 1)
				require.Contains(t, actual.Labels, "foo")
				require.Equal(t, actual.Labels["foo"], "bar")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
			),
		},
		{
			name: "simple-block",
			caddyInput: `labeled {
				label {
					foo bar
				}
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.NotEmpty(t, actual.Labels)
				require.Len(t, actual.Labels, 1)
				require.Contains(t, actual.Labels, "foo")
				require.Equal(t, actual.Labels["foo"], "bar")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
			),
		},
		{
			name: "mulitple-inline",
			caddyInput: `labeled {
				label foo bar
				label spam eggs
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.NotEmpty(t, actual.Labels)
				require.Len(t, actual.Labels, 2)
				require.Contains(t, actual.Labels, "foo")
				require.Equal(t, actual.Labels["foo"], "bar")
				require.Contains(t, actual.Labels, "spam")
				require.Equal(t, actual.Labels["spam"], "eggs")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
				config.WithLabel("spam", "eggs"),
			),
		},
		{
			name: "mulitple-block",
			caddyInput: `labeled {
				label {
					foo bar
					spam eggs
				}
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.NotEmpty(t, actual.Labels)
				require.Len(t, actual.Labels, 2)
				require.Contains(t, actual.Labels, "foo")
				require.Equal(t, actual.Labels["foo"], "bar")
				require.Contains(t, actual.Labels, "spam")
				require.Equal(t, actual.Labels["spam"], "eggs")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
				config.WithLabel("spam", "eggs"),
			),
		},
		{
			name: "mulitple-mixed",
			caddyInput: `labeled {
				label foo bar
				label {
					spam eggs
				}
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.NotEmpty(t, actual.Labels)
				require.Len(t, actual.Labels, 2)
				require.Contains(t, actual.Labels, "foo")
				require.Equal(t, actual.Labels["foo"], "bar")
				require.Contains(t, actual.Labels, "spam")
				require.Equal(t, actual.Labels["spam"], "eggs")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
				config.WithLabel("spam", "eggs"),
			),
		},
		{
			name: "label-too-many-args",
			caddyInput: `labeled {
				label foo bar toomanyargs
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}

func TestLabeledMetadata(t *testing.T) {
	cases := genericTestCases[*Labeled]{
		{
			name: "absent",
			caddyInput: `labeled {
				label foo bar
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.Empty(t, actual.Metadata)
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
			),
		},
		{
			name: "with metadata",
			caddyInput: `labeled {
				label foo bar
				metadata test
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.Equal(t, actual.Metadata, "test")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
				config.WithMetadata("test"),
			),
		},
		{
			name: "metadata-single-arg-quotes",
			caddyInput: `labeled {
				label foo bar
				metadata "Hello, World!"
			}`,
			expectConfig: func(t *testing.T, actual *Labeled) {
				require.Equal(t, actual.Metadata, "Hello, World!")
			},
			expectedOpts: config.LabeledTunnel(
				config.WithLabel("foo", "bar"),
				config.WithMetadata("Hello, World!"),
			),
		},
		{
			name: "metadata-no-args",
			caddyInput: `labeled {
				label foo bar
				metadata
			}`,
			expectUnmarshalErr: true,
		},
		{
			name: "metadata-too-many-args",
			caddyInput: `labeled {
				label foo bar
				metadata test test2
			}`,
			expectUnmarshalErr: true,
		},
	}

	cases.runAll(t)

}
