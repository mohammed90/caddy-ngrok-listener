package ngroklistener

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseTLS(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  TLS
	}{
		{`tls {
			metadata test
		}`, false, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			domain test.domain.com
		}`, false, TLS{Metadata: "test", Domain: "test.domain.com", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			domain
		}`, true, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			domain too manyargs
		}`, true, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			allow 1
		}`, false, TLS{Metadata: "test", AllowCIDR: []string{"1"}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			allow 1 2 3
		}`, false, TLS{Metadata: "test", AllowCIDR: []string{"1", "2", "3"}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			allow
		}`, true, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
		{`tls {
			metadata test
			deny 1
		}`, false, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1"}}},
		{`tls {
			metadata test
			deny 1 2 3
		}`, false, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{"1", "2", "3"}}},
		{`tls {
			metadata test
			deny
		}`, true, TLS{Metadata: "test", AllowCIDR: []string{}, DenyCIDR: []string{}}},
	}

	for i, test := range tests {
		d := caddyfile.NewTestDispenser(test.input)
		tun := TLS{}
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
				t.Errorf("Test %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", i, tun.Metadata, test.expected.Metadata)
			} else if test.expected.Domain != tun.Domain {
				t.Errorf("Test %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", i, tun.Domain, test.expected.Domain)
			} else if !reflect.DeepEqual(test.expected.AllowCIDR, tun.AllowCIDR) {
				t.Errorf("Test %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", i, tun.AllowCIDR, test.expected.AllowCIDR)
			} else if !reflect.DeepEqual(test.expected.DenyCIDR, tun.DenyCIDR) {
				t.Errorf("Test %v: Created TLS (\n%#v\n) does not match expected (\n%#v\n)", i, tun.DenyCIDR, test.expected.DenyCIDR)
			}
		}
	}
}
