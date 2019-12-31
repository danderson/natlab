package main

import (
	"math/rand"
	"net"

	log "github.com/sirupsen/logrus"
)

// PortManager allocates WAN UDP ports according to a configurable policy.
type PortManager struct {
	wanIPs []net.IP
	// map of UDPAddr -> net.Conn bound to port
	allocatedPorts map[UDPAddr]net.Conn
	rng            *rand.Rand
}

// ipRefcount holds an IP address and a reference count.
type ipRefcount struct {
	ip     net.IP
	refcnt int
}

func NewPortManager(wanIPs []net.IP) *PortManager {
	return &PortManager{
		wanIPs:         append([]net.IP(nil), wanIPs...),
		allocatedPorts: map[UDPAddr]net.Conn{},
		rng:            NewRandom(),
	}
}

// Allocate tries to allocate a WAN ip:port for the given clientAddr.
func (p *PortManager) Allocate(clientAddr UDPAddr) (port UDPAddr, close func(), err error) {
	// TODO: more policies, right now we're just doing fully
	// randomized allocation.
	for {
		publicIP := p.wanIPs[p.rng.Intn(len(p.wanIPs))]
		port := 1024 + p.rng.Intn(64511)
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: publicIP, Port: port})
		if err != nil {
			// TODO: log?
			continue
		}

		addr := FromNetUDPAddr(conn.LocalAddr().(*net.UDPAddr))

		p.allocatedPorts[addr] = conn

		return addr, func() { p.delete(addr, conn) }, nil
	}
}

func (p *PortManager) delete(addr UDPAddr, conn net.Conn) {
	if conn2 := p.allocatedPorts[addr]; conn2 != conn {
		log.Panicf("inconsistent state in port manager! Expected conn %v for UDPAddr %s, found %v", conn, addr, conn2)
	}

	delete(p.allocatedPorts, addr)
	conn.Close()
}
