package firewall

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/ihac/firewall/firewall/filter"
	"github.com/miekg/dns"
)

const (
	// QtypeAll is used to match any kinds of DNS records type.
	// NOTE: The value of QtypeAll should be different with other QTYPEs defined in miekg/dns.
	QtypeAll dns.Type = 260
)

var (
	// PrivateNets defines all ip addresses reserved for private networks.
	// i.e., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
	PrivateNets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
)

func init() {
	caddy.RegisterPlugin("firewall", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	f, err := parseFirewall(c)
	if err != nil {
		return err
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		f.Next = next
		return f
	})

	// Register all metrics.
	c.OnStartup(func() error {
		metrics.MustRegister(c, RequestBlockCount, RequestAllowCount)
		return nil
	})
	return nil
}

func parseFirewall(c *caddy.Controller) (firewall, error) {
	f := firewall{}
	/*
	 * firewall [ZONES...] {
	 *   ACTION type QTYPE net SOURCE
	 *   ...
	 * }
	 *
	 * ACTION: allow|block
	 */
	for c.Next() {
		r := Rule{}
		// load <ZONES...>.
		// load <ZONES...>.
		r.Zones = c.RemainingArgs()
		if len(r.Zones) == 0 {
			// if empty, the zones from the configuration block are used.
			r.Zones = make([]string, len(c.ServerBlockKeys))
			copy(r.Zones, c.ServerBlockKeys)
		}
		// strip port and transport.
		for i := range r.Zones {
			r.Zones[i] = plugin.Host(r.Zones[i]).Normalize()
		}

		var err error
		// load all tokens in this block.
		for c.NextBlock() {
			p := Policy{}
			// ACTION type QTYPE net SOURCE
			p.action = strings.ToLower(c.Val())
			if p.action != ALLOW && p.action != BLOCK {
				return f, c.Errf("Unexpected token '%s'; expect '%s' or '%s'", c.Val(), ALLOW, BLOCK)
			}

			// TODO: simplify the syntax and remove tedious code. (@ihac)
			if !c.NextArg() {
				return f, c.ArgErr()
			}
			if strings.ToLower(c.Val()) != "type" {
				return f, c.Errf("Unexpected token '%s'; expect 'type'", c.Val())
			}

			if !c.NextArg() {
				return f, c.ArgErr()
			}
			p.qtype, err = parseQype(c.Val())
			if err != nil {
				return f, err
			}

			if !c.NextArg() {
				return f, c.ArgErr()
			}

			var rawNetRanges []string
			sourceType := strings.ToLower(c.Val())
			if sourceType == "net" {
				rawNetRanges = preprocessNetworks(c.RemainingArgs())
			} else if sourceType == "file" {
				if !c.NextArg() {
					return f, c.ArgErr()
				}
				rawNetRanges, err = loadNetworksFromLocalFile(c.Val())
				if err != nil {
					return f, c.Errf("Unable to load networks from local file: %v", err)
				}
			} else {
				return f, c.Errf("Unexpected token '%s'; expect 'net'", c.Val())
			}

			if len(rawNetRanges) == 0 {
				return f, c.Errf("no network is specified")
			}
			var sources []net.IPNet
			for _, rawNet := range rawNetRanges {
				rawNet = normalize(rawNet)
				_, source, err := net.ParseCIDR(rawNet)
				if err != nil {
					return f, c.Errf("Illegal CIDR notation '%s'", rawNet)
				}
				sources = append(sources, *source)
			}
			p.filter, err = filter.New("trie", sources)
			if err != nil {
				return f, c.Errf("Unable to initialize filter: %v", err)
			}
			r.Policies = append(r.Policies, p)
		}
		f.Rules = append(f.Rules, r)
	}
	return f, nil
}

func normalize(rawNet string) string {
	if idx := strings.IndexAny(rawNet, "/"); idx >= 0 {
		return rawNet
	}
	return rawNet + "/32"
}

func preprocessNetworks(rawNets []string) []string {
	var nets []string
	for _, rawNet := range rawNets {
		switch rawNet {
		case "PRIVATE":
			for _, pn := range PrivateNets {
				nets = append(nets, pn)
			}
		case "LOCAL":
			intfs, err := net.Interfaces()
			if err != nil {
				log.Errorf("Failed to get all network interfaces: %v", err)
				continue
			}
			for _, intf := range intfs {
				addrs, err := intf.Addrs()
				if err != nil {
					log.Errorf("Failed to get addresses from interface %s: %v", intf.Name, err)
					continue
				}
				for _, addr := range addrs {
					n := addr.String()
					// TODO: support IPv6. (@ihac)
					// ":" should be enough to distinguish IPv4 and IPv6.
					if strings.Contains(n, ":") {
						continue
					}
					nets = append(nets, n)
				}
			}
		case "*":
			fallthrough
		case "ANY":
			return []string{"0.0.0.0/0"}
		default:
			nets = append(nets, rawNet)
		}

	}
	return nets
}

func loadNetworksFromLocalFile(fileName string) ([]string, error) {
	var nets []string
	file, err := os.Open(fileName)
	defer file.Close()
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		// skip empty line.
		if line == "" {
			continue
		}
		nets = append(nets, line)
	}
	return nets, nil
}

func stripComment(line string) string {
	commentCh := "#"
	if idx := strings.IndexAny(line, commentCh); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimLeftFunc(line, unicode.IsSpace)
	return strings.TrimRightFunc(line, unicode.IsSpace)
}

// TODO: dns.Type == QType? (@ihac)
func parseQype(raw string) (dns.Type, error) {
	switch raw {
	case "A":
		return dns.Type(dns.TypeA), nil
	case "AAAA":
		return dns.Type(dns.TypeAAAA), nil
	case "AFSDB":
		return dns.Type(dns.TypeAFSDB), nil
	case "CAA":
		return dns.Type(dns.TypeCAA), nil
	case "CDNSKEY":
		return dns.Type(dns.TypeCDNSKEY), nil
	case "CDS":
		return dns.Type(dns.TypeCDS), nil
	case "CERT":
		return dns.Type(dns.TypeCERT), nil
	case "CNAME":
		return dns.Type(dns.TypeCNAME), nil
	case "DHCID":
		return dns.Type(dns.TypeDHCID), nil
	case "DLV":
		return dns.Type(dns.TypeDLV), nil
	case "DNAME":
		return dns.Type(dns.TypeDNAME), nil
	case "DNSKEY":
		return dns.Type(dns.TypeDNSKEY), nil
	case "DS":
		return dns.Type(dns.TypeDS), nil
	case "HIP":
		return dns.Type(dns.TypeHIP), nil
	case "KEY":
		return dns.Type(dns.TypeKEY), nil
	case "KX":
		return dns.Type(dns.TypeKX), nil
	case "LOC":
		return dns.Type(dns.TypeLOC), nil
	case "MX":
		return dns.Type(dns.TypeMX), nil
	case "NAPTR":
		return dns.Type(dns.TypeNAPTR), nil
	case "NS":
		return dns.Type(dns.TypeNS), nil
	case "NSEC":
		return dns.Type(dns.TypeNSEC), nil
	case "NSEC3":
		return dns.Type(dns.TypeNSEC3), nil
	case "NSEC3PARAM":
		return dns.Type(dns.TypeNSEC3PARAM), nil
	case "OPENPGPKEY":
		return dns.Type(dns.TypeOPENPGPKEY), nil
	case "PTR":
		return dns.Type(dns.TypePTR), nil
	case "RRSIG":
		return dns.Type(dns.TypeRRSIG), nil
	case "RP":
		return dns.Type(dns.TypeRP), nil
	case "SIG":
		return dns.Type(dns.TypeSIG), nil
	case "SMIMEA":
		return dns.Type(dns.TypeSMIMEA), nil
	case "SOA":
		return dns.Type(dns.TypeSOA), nil
	case "SRV":
		return dns.Type(dns.TypeSRV), nil
	case "SSHFP":
		return dns.Type(dns.TypeSSHFP), nil
	case "TA":
		return dns.Type(dns.TypeTA), nil
	case "TKEY":
		return dns.Type(dns.TypeTKEY), nil
	case "TLSA":
		return dns.Type(dns.TypeTLSA), nil
	case "TSIG":
		return dns.Type(dns.TypeTSIG), nil
	case "TXT":
		return dns.Type(dns.TypeTXT), nil
	case "URI":
		return dns.Type(dns.TypeURI), nil
	case "ANY":
		fallthrough
	case "*":
		return QtypeAll, nil
	default:
		return 0, fmt.Errorf("Unexpected token '%s'; expect legal QTYPE", raw)
	}
}
