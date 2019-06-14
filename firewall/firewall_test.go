package firewall

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/mholt/caddy"
	"github.com/miekg/dns"
)

type testResponseWriter struct {
	remoteIP net.Addr
	Rcode    int
}

func (t *testResponseWriter) setRemoteIP(rawIP string) {
	ip := net.ParseIP(rawIP)
	port := 65667
	t.remoteIP = &net.UDPAddr{IP: ip, Port: port, Zone: ""}
}

// LocalAddr returns the local address, 127.0.0.1:53.
func (t *testResponseWriter) LocalAddr() net.Addr {
	ip := net.ParseIP("127.0.0.1")
	port := 53
	return &net.UDPAddr{IP: ip, Port: port, Zone: ""}
}

// RemoteAddr returns the remote address, always 10.240.0.1:40212.
func (t *testResponseWriter) RemoteAddr() net.Addr {
	return t.remoteIP
}

// WriteMsg implement dns.ResponseWriter interface.
func (t *testResponseWriter) WriteMsg(m *dns.Msg) error {
	t.Rcode = m.Rcode
	return nil
}

// Write implement dns.ResponseWriter interface.
func (t *testResponseWriter) Write(buf []byte) (int, error) { return len(buf), nil }

// Close implement dns.ResponseWriter interface.
func (t *testResponseWriter) Close() error { return nil }

// TsigStatus implement dns.ResponseWriter interface.
func (t *testResponseWriter) TsigStatus() error { return nil }

// TsigTimersOnly implement dns.ResponseWriter interface.
func (t *testResponseWriter) TsigTimersOnly(bool) { return }

// Hijack implement dns.ResponseWriter interface.
func (t *testResponseWriter) Hijack() { return }

func NewTestControllerWithZones(serverType, input string, zones []string) *caddy.Controller {
	ctr := caddy.NewTestController(serverType, input)
	for _, zone := range zones {
		ctr.ServerBlockKeys = append(ctr.ServerBlockKeys, zone)
	}
	return ctr
}

func Test_firewall_ServeDNS(t *testing.T) {
	type args struct {
		domain   string
		sourceIP string
		qtype    uint16
	}
	tests := []struct {
		name      string
		ctr       *caddy.Controller
		args      args
		wantRcode int
		wantErr   bool
	}{
		{
			"Blacklist 1 BLOCKED",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type A from 192.168.0.0/16
			}`),
			args{
				"www.example.org.",
				"192.168.0.2",
				dns.TypeA,
			},
			dns.RcodeRefused,
			false,
		},
		{
			"Blacklist 1 ALLOWED",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type A from 192.168.0.0/16
			}`),
			args{
				"www.example.org.",
				"192.167.0.2",
				dns.TypeA,
			},
			dns.RcodeSuccess,
			false,
		},
		{
			"Blacklist 2 BLOCKED",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type ANY from 192.168.0.0/16
			}`),
			args{
				"www.example.org.",
				"192.168.0.2",
				dns.TypeAAAA,
			},
			dns.RcodeRefused,
			false,
		},
		{
			"Blacklist 3 BLOCKED",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type A from ANY
			}`),
			args{
				"www.example.org.",
				"10.1.0.2",
				dns.TypeA,
			},
			dns.RcodeRefused,
			false,
		},
		{
			"Blacklist 3 ALLOWED",
			caddy.NewTestController("dns", `
			firewall example.org {
				block type A from ANY
			}`),
			args{
				"www.example.org.",
				"10.1.0.2",
				dns.TypeAAAA,
			},
			dns.RcodeSuccess,
			false,
		},
		{
			"Whitelist 1 ALLOWED",
			caddy.NewTestController("dns", `
			firewall example.org {
				allow type ANY from 192.168.0.0/16
				block type ANY from ANY
			}`),
			args{
				"www.example.org.",
				"192.168.0.2",
				dns.TypeA,
			},
			dns.RcodeSuccess,
			false,
		},
		{
			"Whitelist 1 REFUSED",
			caddy.NewTestController("dns", `
			firewall example.org {
				allow type ANY from 192.168.0.0/16
				block type ANY from ANY
			}`),
			args{
				"www.example.org.",
				"10.1.0.2",
				dns.TypeA,
			},
			dns.RcodeRefused,
			false,
		},
		{
			"Fine-Grained 1 REFUSED",
			NewTestControllerWithZones("dns", `
			firewall a.example.org {
				block type ANY from 192.168.1.0/24
			}`, []string{"example.org"}),
			args{
				"a.example.org.",
				"192.168.1.2",
				dns.TypeA,
			},
			dns.RcodeRefused,
			false,
		},
		{
			"Fine-Grained 1 ALLOWED",
			NewTestControllerWithZones("dns", `
			firewall a.example.org {
				block type ANY from 192.168.1.0/24
			}`, []string{"example.org"}),
			args{
				"www.example.org.",
				"192.168.1.2",
				dns.TypeA,
			},
			dns.RcodeSuccess,
			false,
		},
		{
			"Fine-Grained 2 REFUSED",
			NewTestControllerWithZones("dns", `
			firewall {
				block type ANY from 192.168.1.0/24
			}`, []string{"example.org"}),
			args{
				"a.example.org.",
				"192.168.1.2",
				dns.TypeA,
			},
			dns.RcodeRefused,
			false,
		},
		{
			"Fine-Grained 2 ALLOWED",
			NewTestControllerWithZones("dns", `
			firewall {
				block type ANY from 192.168.1.0/24
			}`, []string{"example.org"}),
			args{
				"a.example.com.",
				"192.168.1.2",
				dns.TypeA,
			},
			dns.RcodeSuccess,
			false,
		},
		// TODO: Add more test cases. (@ihac)
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := parseFirewall(tt.ctr)
			f.Next = test.NextHandler(dns.RcodeSuccess, nil)
			if err != nil {
				t.Errorf("cannot parse firewall from config: %v", err)
			}

			w := &testResponseWriter{}
			m := new(dns.Msg)
			w.setRemoteIP(tt.args.sourceIP)
			m.SetQuestion(tt.args.domain, tt.args.qtype)
			_, err = f.ServeDNS(ctx, w, m)
			if (err != nil) != tt.wantErr {
				t.Errorf("firewall.ServeDNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if w.Rcode != tt.wantRcode {
				t.Errorf("firewall.ServeDNS() Rcode = %v, want %v", w.Rcode, tt.wantRcode)
			}
		})
	}
}
