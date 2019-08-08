package filter

import "net"

type naiveFilter struct {
	subnets []net.IPNet
}

var _ Filter = &naiveFilter{}

func (nf *naiveFilter) Add(subnet net.IPNet) error {
	nf.subnets = append(nf.subnets, subnet)
	return nil
}

func (nf *naiveFilter) Contains(ip net.IP) bool {
	for _, subnet := range nf.subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func newNaiveFilter(subnets []net.IPNet) (*naiveFilter, error) {
	return &naiveFilter{
		subnets: subnets,
	}, nil
}
