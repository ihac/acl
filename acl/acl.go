package acl

import (
	"context"
	"fmt"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/ihac/acl/acl/filter"
)

type acl struct {
	Next plugin.Handler

	Rules []Rule
}

// Rule defines a list of Zones and some ACL policies which will be
// enforced on them.
type Rule struct {
	Zones    []string
	Policies []Policy
}

// Policy defines the ACL policy for DNS queries.
// A policy performs the specified action (block/allow) on all DNS queries
// matched by source IP or QTYPE.
type Policy struct {
	action  string
	qtype   dns.Type
	filter  filter.Filter
}

const (
	// ALLOW allows authorized queries to recurse.
	ALLOW string = "allow"
	// BLOCK blocks unauthorized queries towards protected DNS zones.
	BLOCK string = "block"
)

func (a acl) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	for _, rule := range a.Rules {
		// check zone
		zone := plugin.Zones(rule.Zones).Matches(state.Name())
		if zone == "" {
			continue
		}
		isBlocked, err := shouldBlock(rule.Policies, w, r)
		if err != nil {
			return dns.RcodeRefused, err
		}
		if isBlocked {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			RequestBlockCount.WithLabelValues(metrics.WithServer(ctx), zone).Inc()
			// TODO: should we return Success here? (@ihac)
			return dns.RcodeSuccess, nil
		}
	}
	RequestAllowCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
	return plugin.NextOrFailure(state.Name(), a.Next, ctx, w, r)
}

func shouldBlock(policies []Policy, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	state := request.Request{W: w, Req: r}

	ip := net.ParseIP(state.IP())
	if ip == nil {
		return true, fmt.Errorf("Illegal source ip '%s'", state.IP())
	}

	if len(r.Question) != 1 {
		// TODO: what if #question == 0 or > 1? (@ihac)
		return false, nil
	}
	qtype := r.Question[0].Qtype
	for _, policy := range policies {
		if !policy.filter.Contains(ip) {
			continue
		}

		if dns.Type(qtype) != policy.qtype && policy.qtype != QtypeAll {
			continue
		}
		// matched.
		switch policy.action {
		case ALLOW:
			return false, nil
		case BLOCK:
			return true, nil
		}
	}
	return false, nil
}

func (a acl) Name() string {
	return "acl"
}
