package firewall

import (
	"context"
	"fmt"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
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

func (f firewall) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	// check zone
	zone := plugin.Zones(f.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(state.Name(), f.Next, ctx, w, r)
	}

	ip := net.ParseIP(state.IP())
	if ip == nil {
		return dns.RcodeRefused, fmt.Errorf("Illegal source ip '%s'", state.IP())
	}
	if len(r.Question) != 1 {
		// TODO: what if #question == 0 or > 1? (@ihac)
		return plugin.NextOrFailure(state.Name(), f.Next, ctx, w, r)
	}
	qtype := r.Question[0].Qtype

	isBlocked := false
	for _, rule := range f.Rules {
		if !rule.source.Contains(ip) {
			continue
		}
		if dns.Type(qtype) != rule.qtype && rule.qtype != QtypeAll {
			continue
		}

		// matched.
		switch rule.action {
		case ALLOW:
			goto Resp
		case BLOCK:
			isBlocked = true
			goto Resp
		}
	}

Resp:
	if isBlocked {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		// TODO: should we return Success here? (@ihac)
		return dns.RcodeSuccess, nil
	}
	// allow to recurse.
	return plugin.NextOrFailure(state.Name(), f.Next, ctx, w, r)
}

func (f firewall) Name() string {
	return "firewall"
}
