package firewall

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type firewall struct {
	Next plugin.Handler

	Rules []Rule
	Zones []string
}

// Rule defines the ACL policy for DNS queries.
// A rule performs the specified action (block/allow) on all DNS queries
// matched by source IP or QTYPE.
type Rule struct {
	action string
	qtype  dns.Type
	source *net.IPNet
}

const (
	// ALLOW allows authorized queries to recurse.
	ALLOW string = "allow"
	// BLOCK blocks unauthorized queries towards protected DNS zones.
	BLOCK string = "block"
)

// TODO: impl. (@ihac)
func (f firewall) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	return 0, nil
}

// TODO: impl. (@ihac)
func (f firewall) Name() string {
	return "firewall"
}
