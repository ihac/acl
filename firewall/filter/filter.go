package filter

import (
	"net"
	"fmt"
)

// Filter allows to whether an IP address is present in
// a set of IP addresses or subnets (in CIDR notation).
type Filter interface {
	Add(net.IPNet) error
	Contains(net.IP) bool
}

func New(filterType string, subnets []net.IPNet) (Filter, error) {
	switch filterType {
	case "naive":
		return newNaiveFilter(subnets)
	case "cuckoo":
		return newCuckooFilter(subnets)
	default:
		return nil, fmt.Errorf("unrecognized filter type: %s", filterType)
	}
}