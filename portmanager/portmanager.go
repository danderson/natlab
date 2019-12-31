package portmanager

import (
	"math/rand"
	"net"
)

// A PortManager allocates WAN ip:ports on demand.
type PortManager interface {
	Allocate(clientAddr *net.UDPAddr) (port *net.UDPAddr, close func(), err error)
}

// PortManager allocates WAN UDP ports according to a configurable policy.
type ipAndPortRandomizingPortManager struct {
	wanIPs []net.IP
	rng    *rand.Rand
}

// ipRefcount holds an IP address and a reference count.
type ipRefcount struct {
	ip     net.IP
	refcnt int
}

func New(wanIPs []net.IP) PortManager {
	return &ipAndPortRandomizingPortManager{
		wanIPs: append([]net.IP(nil), wanIPs...),
		rng:    NewRandom(),
	}
}

// Allocate tries to allocate a WAN ip:port for the given clientAddr.
func (p *ipAndPortRandomizingPortManager) Allocate(clientAddr *net.UDPAddr) (port *net.UDPAddr, close func(), err error) {
	// TODO: more policies, right now we're just doing fully
	// randomized allocation.
	for {
		publicIP := p.wanIPs[p.rng.Intn(len(p.wanIPs))]
		port := 1024 + p.rng.Intn(64511)
		addr, close, err := allocateAddr(&net.UDPAddr{IP: publicIP, Port: port})
		if err != nil {
			// TODO: log?
			continue
		}

		return addr, close, nil
	}
}

// AllocateAddr tries to allocate exactly the requested address.
func allocateAddr(wantedAddr *net.UDPAddr) (port *net.UDPAddr, close func(), err error) {
	conn, err := net.ListenUDP("udp4", wantedAddr)
	if err != nil {
		return nil, nil, err
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr, func() { conn.Close() }, nil
}
