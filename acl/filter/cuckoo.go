package filter

import (
	"net"

	"github.com/coredns/coredns/plugin/pkg/log"
	cuckoo "github.com/seiflotfy/cuckoofilter"
)

const minFilterSize = 500

type cuckooFilter struct {
	*cuckoo.Filter
	subnets []net.IPNet
}

var _ Filter = &cuckooFilter{}

func (cf *cuckooFilter) Add(subnet net.IPNet) error {
	if isSingleIP(subnet) {
		ip := subnet.IP.To4()
		ok := cf.Filter.InsertUnique(ip)
		if !ok {
			log.Warningf("Failed to insert IP '%s' to filter", ip)
		}
	} else {
		cf.subnets = append(cf.subnets, subnet)
	}
	return nil
}

func (cf *cuckooFilter) Contains(ip net.IP) bool {
	if cf.Filter.Lookup(ip.To4()) {
		return true
	}
	for _, subnet := range cf.subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func newCuckooFilter(subnets []net.IPNet) (*cuckooFilter, error) {
	netsCount := len(subnets)
	filterSize := netsCount + netsCount/2
	if filterSize < minFilterSize {
		filterSize = minFilterSize
	}

	filter := cuckoo.NewFilter(uint(filterSize))
	cf := cuckooFilter{
		Filter: filter,
	}
	for _, subnet := range subnets {
		err := cf.Add(subnet)
		if err != nil {
			return nil, err
		}
	}
	return &cf, nil
}

func isSingleIP(subnet net.IPNet) bool {
	for _, b := range subnet.Mask {
		if b != 255 {
			return false
		}
	}
	return true
}
