package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseTCP(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  TCP
	}{
		{`tcp {
			metadata test
		}`, false, TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tcp {
			metadata test
		}`, false, TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tcp {
			metadata test
			allow 1
		}`, false, TCP{Metadata: "test", AllowCIDR: []string{"1"}, DenyCIDR: []string{}}},
		{`tcp {
			metadata test
			allow 1 2 3
		}`, false, TCP{Metadata: "test", AllowCIDR: []string{"1", "2", "3"}, DenyCIDR: []string{}}},
		{`tcp {
			metadata test
			allow
		}`, true, TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tcp {
			metadata test
			deny 1
		}`, false, TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1"}}},
		{`tcp {
			metadata test
			deny 1 2 3
		}`, false, TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1", "2", "3"}}},
		{`tcp {
			metadata test
			deny
		}`, true, TCP{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TCP{}
		err := tun.UnmarshalCaddyfile(d)
		tun.Provision(caddy.Context{})

		if test.shouldErr {
			if err == nil {
				t.Errorf("Test %v: Expected error but found nil", i)
			}
		} else {
			if err != nil {
				t.Errorf("Test %v: Expected no error but found error: %v", i, err)
			} else if test.expected.Metadata != tun.Metadata {
				t.Errorf("Test %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, tun.Metadata, test.expected.Metadata)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test %v: Created TCP (\n%#v\n) does not match expected (\n%#v\n)", i, tun.DenyCIDR, test.expected.DenyCIDR)
			}
		}
	}
}
