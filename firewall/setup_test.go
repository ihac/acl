package firewall

import (
	"os"
	"testing"

	"github.com/caddyserver/caddy"
)

var (
	localfiles = map[string]string{
		"acl-example-1.txt": `10.218.128.0/24
35.39.53.223/32
43.105.127.35/18`,
	}
)

func init() {
	for k, v := range localfiles {
		file, err := os.Create(k)
		defer file.Close()
		if err != nil {
			panic(err)
		}
		_, err = file.Write([]byte(v))
		if err != nil {
			panic(err)
		}
	}
}

func cleanup() {
	for k := range localfiles {
		err := os.Remove(k)
		if err != nil {
			panic(err)
		}
	}
}

func Test_setup(t *testing.T) {
	defer cleanup()

	tests := []struct {
		name    string
		ctr     *caddy.Controller
		wantErr bool
	}{
		{
			"Blacklist 1",
			caddy.NewTestController("dns", `
			firewall {
				block type A net 192.168.0.0/16
			}
			`),
			false,
		},
		{
			"Blacklist 2",
			caddy.NewTestController("dns", `
			firewall {
				block type ANY net 192.168.0.0/16
			}
			`),
			false,
		},
		{
			"Blacklist 3",
			caddy.NewTestController("dns", `
			firewall {
				block type A net ANY
			}
			`),
			false,
		},
		{
			"Blacklist 4",
			caddy.NewTestController("dns", `
			firewall {
				allow type ANY net 192.168.1.0/24
				block type ANY net 192.168.0.0/16
			}
			`),
			false,
		},
		{
			"Whitelist 1",
			caddy.NewTestController("dns", `
			firewall {
				allow type ANY net 192.168.0.0/16
				block type ANY net ANY
			}
			`),
			false,
		},
		{
			"fine-grained 1",
			caddy.NewTestController("dns", `
			firewall a.example.org {
				block type ANY net 192.168.1.0/24
			}
			`),
			false,
		},
		{
			"fine-grained 2",
			caddy.NewTestController("dns", `
			firewall a.example.org {
				block type ANY net 192.168.1.0/24
			}
			firewall b.example.org {
				block type ANY net 192.168.2.0/24
			}
			`),
			false,
		},
		{
			"multiple-networks 1",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type ANY net 192.168.1.0/24 192.168.3.0/24
			}
			`),
			false,
		},
		{
			"multiple-networks 2",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type ANY net 192.168.3.0/24
			}
			`),
			false,
		},
		{
			"Keyword PRIVATE 1",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type ANY net PRIVATE
			}
			`),
			false,
		},
		{
			"Keyword LOCAL 1",
			caddy.NewTestController("dns", `
			firewall example.org {
				allow type ANY net LOCAL
				block type ANY net ANY
			}
			`),
			false,
		},
		{
			"Local file 1",
			caddy.NewTestController("dns", `
			firewall {
				block type A file acl-example-1.txt
			}
			`),
			false,
		},
		{
			"Missing argument 1",
			caddy.NewTestController("dns", `
			firewall {
				block A net 192.168.0.0/16
			}
			`),
			true,
		},
		{
			"Missing argument 2",
			caddy.NewTestController("dns", `
			firewall {
				block type net 192.168.0.0/16
			}
			`),
			true,
		},
		{
			"Illegal argument 1",
			caddy.NewTestController("dns", `
			firewall {
				block type ABC net 192.168.0.0/16
			}
			`),
			true,
		},
		{
			"Illegal argument 2",
			caddy.NewTestController("dns", `
			firewall {
				blck type A net 192.168.0.0/16
			}
			`),
			true,
		},
		{
			"Illegal argument 3",
			caddy.NewTestController("dns", `
			firewall {
				block type A net 192.168.0/16
			}
			`),
			true,
		},
		{
			"Illegal argument 4",
			caddy.NewTestController("dns", `
			firewall {
				block type A net 192.168.0.0/33
			}
			`),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := setup(tt.ctr); (err != nil) != tt.wantErr {
				t.Errorf("setup() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
