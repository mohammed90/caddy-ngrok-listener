package ngroklistener

import (
	"context"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.ngrok.com/ngrok/config"
)

type TestConfig interface {
	Provision(caddy.Context) error
	UnmarshalCaddyfile(*caddyfile.Dispenser) error
	NgrokTunnel() config.Tunnel
}

type genericTest[C TestConfig] struct {
	name               string
	caddyInput         string
	expectUnmarshalErr bool
	expectProvisionErr bool
	expectConfig       func(t *testing.T, actual C)
	expectedOpts       config.Tunnel
}

type genericTestCases[C TestConfig] []genericTest[C]

func (gt genericTest[C]) run(t *testing.T) {
	t.Run(gt.name, func(t *testing.T) {
		d := caddyfile.NewTestDispenser(gt.caddyInput)
		var dummy C
		ct := reflect.TypeOf(dummy)
		tun := reflect.New(ct.Elem()).Interface().(C)
		err := tun.UnmarshalCaddyfile(d)

		if gt.expectUnmarshalErr {
			require.NotNil(t, err)
			return
		} else {
			require.Nil(t, err)
			if assert.NotNil(t, gt.expectConfig) {
				gt.expectConfig(t, tun)
			}
		}

		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		err = tun.Provision(ctx)

		if gt.expectProvisionErr {
			require.NotNil(t, err)
			return
		} else {
			require.Nil(t, err)
			ngrokTun := tun.NgrokTunnel()
			require.Equal(t, gt.expectedOpts, ngrokTun)
		}

	})
}

func (gtcs genericTestCases[C]) runAll(t *testing.T) {
	for _, tc := range gtcs {
		tc.run(t)
	}
}

type NgrokTestConfig interface {
	Provision(caddy.Context) error
	UnmarshalCaddyfile(*caddyfile.Dispenser) error
}
type genericNgrokTest[C NgrokTestConfig] struct {
	name               string
	caddyInput         string
	expectUnmarshalErr bool
	expectProvisionErr bool
	expectConfig       func(t *testing.T, actual C)
}

type genericNgrokTestCases[C NgrokTestConfig] []genericNgrokTest[C]

func (gt genericNgrokTest[C]) run(t *testing.T) {
	t.Run(gt.name, func(t *testing.T) {
		d := caddyfile.NewTestDispenser(gt.caddyInput)
		var dummy C
		ct := reflect.TypeOf(dummy)
		ngrok := reflect.New(ct.Elem()).Interface().(C)
		err := ngrok.UnmarshalCaddyfile(d)

		if gt.expectUnmarshalErr {
			require.NotNil(t, err)
			return
		} else {
			require.Nil(t, err)
			if assert.NotNil(t, gt.expectConfig) {
				gt.expectConfig(t, ngrok)
			}
		}

		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		err = ngrok.Provision(ctx)

		if gt.expectProvisionErr {
			require.NotNil(t, err)
			return
		} else {
			require.Nil(t, err)
		}

	})
}

func (gtcs genericNgrokTestCases[C]) runAll(t *testing.T) {
	for _, tc := range gtcs {
		tc.run(t)
	}
}
