package filter

import (
	"net"

	cuckoo "github.com/seiflotfy/cuckoofilter"
)

type cuckooFilter struct {
	cuckoo.Filter
}

var _ Filter = &cuckooFilter{}

func (cf *cuckooFilter) Add(subnet net.IPNet) error {
	return nil
}

func (cf *cuckooFilter) Contains(ip net.IP) bool {
	return false
}

func newCuckooFilter(subnets []net.IPNet) (*cuckooFilter, error) {
	return nil, nil
}
