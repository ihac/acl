package firewall

import (
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/mholt/caddy"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterPlugin("firewall", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	f := firewall{}
	/*
	 * firewall [ZONES...] {
	 *   ACTION type QTYPE from SOURCE
	 *   ...
	 * }
	 *
	 * ACTION: allow|block
	 */
	for c.Next() {
		// load <ZONES...>.
		f.Zones = c.RemainingArgs()
		if len(f.Zones) == 0 {
			// if empty, the zones from the configuration block are used.
			f.Zones = make([]string, len(c.ServerBlockKeys))
			copy(f.Zones, c.ServerBlockKeys)
		}
		// strip port and transport.
		for i := range f.Zones {
			f.Zones[i] = plugin.Host(f.Zones[i]).Normalize()
		}

		var err error
		// load all tokens in this block.
		for c.NextBlock() {
			rule := Rule{}
			// ACTION type QTYPE from SOURCE
			rule.action = strings.ToLower(c.Val())
			if rule.action != ALLOW && rule.action != BLOCK {
				return c.Errf("Unexpected token '%s'; expect '%s' or '%s'", c.Val(), ALLOW, BLOCK)
			}

			// TODO: simplify the syntax and remove tedious code. (@ihac)
			if !c.NextArg() {
				return c.ArgErr()
			}
			if strings.ToLower(c.Val()) != "type" {
				return c.Errf("Unexpected token '%s'; expect 'type'", c.Val())
			}

			if !c.NextArg() {
				return c.ArgErr()
			}
			rule.qtype, err = parseQype(c.Val())
			if err != nil {
				return err
			}

			if !c.NextArg() {
				return c.ArgErr()
			}
			if strings.ToLower(c.Val()) != "from" {
				return c.Errf("Unexpected token '%s'; expect 'from'", c.Val())
			}

			if !c.NextArg() {
				return c.ArgErr()
			}
			_, rule.source, err = net.ParseCIDR(c.Val())
			if err != nil {
				return c.Errf("Illegal CIDR notation '%s'", c.Val())
			}

			f.Rules = append(f.Rules, rule)
		}
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		f.Next = next
		return f
	})
	return nil
}

func parseQype(raw string) (dns.Type, error) {
	// TODO: add more qtype. (@ihac)
	switch raw {
	case "A":
		return dns.Type(dns.TypeA), nil
	case "AAAA":
		return dns.Type(dns.TypeAAAA), nil
	default:
		return 0, fmt.Errorf("Unexpected token '%s'; expect legal QTYPE", raw)
	}
}
