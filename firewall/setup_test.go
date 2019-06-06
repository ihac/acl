package firewall

import (
	"testing"

	"github.com/mholt/caddy"
)

func Test_setup(t *testing.T) {
	tests := []struct {
		name    string
		ctr    *caddy.Controller
		wantErr bool
	}{
		{
			"Blacklist 1",
			caddy.NewTestController("dns", `
			firewall {
				block type A from 192.168.0.0/16
			}
			`), 
			false,
		},
		{
			"Blacklist 2",
			caddy.NewTestController("dns", `
			firewall {
				block type ANY from 192.168.0.0/16
			}
			`), 
			false,
		},
		{
			"Blacklist 3",
			caddy.NewTestController("dns", `
			firewall {
				block type A from ANY
			}
			`), 
			false,
		},
		{
			"Blacklist 4",
			caddy.NewTestController("dns", `
			firewall {
				allow type ANY from 192.168.1.0/24
				block type ANY from 192.168.0.0/16
			}
			`), 
			false,
		},
		{
			"Whitelist 1",
			caddy.NewTestController("dns", `
			firewall {
				allow type ANY from 192.168.0.0/16
				block type ANY from ANY
			}
			`), 
			false,
		},
		{
			"fine-grained 1",
			caddy.NewTestController("dns", `
			firewall a.example.org {
				block type ANY from 192.168.1.0/24
			}
			`), 
			false,
		},
		{
			"fine-grained 2",
			caddy.NewTestController("dns", `
			firewall a.example.org {
				block type ANY from 192.168.1.0/24
			}
			firewall b.example.org {
				block type ANY from 192.168.2.0/24
			}
			`), 
			false,
		},
		{
			"Missing argument 1",
			caddy.NewTestController("dns", `
			firewall {
				block A from 192.168.0.0/16
			}
			`), 
			true,
		},
		{
			"Missing argument 2",
			caddy.NewTestController("dns", `
			firewall {
				block type from 192.168.0.0/16
			}
			`), 
			true,
		},
		{
			"Illegal argument 1",
			caddy.NewTestController("dns", `
			firewall {
				block type ABC from 192.168.0.0/16
			}
			`), 
			true,
		},
		{
			"Illegal argument 2",
			caddy.NewTestController("dns", `
			firewall {
				blck type A from 192.168.0.0/16
			}
			`), 
			true,
		},
		{
			"Illegal argument 3",
			caddy.NewTestController("dns", `
			firewall {
				block type A from 192.168.0/16
			}
			`), 
			true,
		},
		{
			"Illegal argument 4",
			caddy.NewTestController("dns", `
			firewall {
				block type A from 192.168.0.0/33
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
