package portmanager

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
)

type PortMatching int
type AddressPairing int

const (
	// Prefer WAN port matching client source port, but pick another
	// if not possible.
	PortMatchingSoft PortMatching = iota
	// WAN port must match client source port, even if this stomps on
	// an existing mapping.
	PortMatchingHard
	// Client source port has no influence over WAN port.
	PortMatchingNone

	// All the mappings for a client IP must be on the same WAN
	// IP. New allocations fail if no ports are available on the
	// selected WAN IP.
	AddressPairingHard AddressPairing = iota
	// Client IP has no influence over the selected WAN IP.
	AddressPairingNone
)

type Config struct {
	// WAN IPs on which to allocate ports.
	WANIPs []net.IP

	// How do a client's source IP and port influence the allocation
	// of a WAN IP and port?
	PortMatching   PortMatching
	AddressPairing AddressPairing
}

// A PortManager allocates WAN ip:ports on demand.
type PortManager struct {
	config *Config
	rng    *rand.Rand
	// ip.String() -> allocated net.Conn
	allocated map[string]net.Conn
}

// ipRefcount holds an IP address and a reference count.
type ipRefcount struct {
	ip     net.IP
	refcnt int
}

func New(config *Config) *PortManager {
	return &PortManager{
		config:    config,
		rng:       NewRandom(),
		allocated: map[string]net.Conn{},
	}
}

// Allocate tries to allocate a WAN ip:port for the given clientAddr.
func (p *PortManager) AllocateUDP(clientAddr *net.UDPAddr) (port *net.UDPAddr, close func(), err error) {
	conn, err := p.allocate(clientAddr)
	if err != nil {
		return nil, nil, err
	}

	addr := conn.LocalAddr().(*net.UDPAddr)
	close = func() { p.deleteConn(addr.String()) }

	p.allocated[addr.String()] = conn

	return addr, close, nil
}

func (p *PortManager) deleteConn(addr string) {
	conn := p.allocated[addr]
	delete(p.allocated, addr)
	conn.Close()
}

func (p *PortManager) allocate(clientAddr *net.UDPAddr) (net.Conn, error) {
	switch p.config.AddressPairing {
	case AddressPairingNone:
		for attempts := 0; attempts < 256; attempts++ {
			ip := p.config.WANIPs[p.rng.Intn(len(p.config.WANIPs))]
			conn, err := p.allocatePort(clientAddr.Port, ip)
			if err == nil {
				// TODO: be more discriminating, "address in use" is the
				// error that's continuable.
				return conn, nil
			}
		}
		return nil, fmt.Errorf("no available WAN ports")

	case AddressPairingHard:
		// Deterministically pick one IP in the available pool. It's
		// not uniform.
		sum := sha256.Sum256([]byte(clientAddr.IP))
		h := int(binary.BigEndian.Uint32(sum[:4]))
		publicIP := p.config.WANIPs[h%len(p.config.WANIPs)]
		// We're only allowed to allocate from the deterministic IP,
		// so if port selection fails, we fail as well.
		return p.allocatePort(clientAddr.Port, publicIP)

	default:
		panic("unimplemented case")
	}
}

// allocatePort tries to allocate a port on the given IP, according to
// the port policy in Config.
func (p *PortManager) allocatePort(clientPort int, ip net.IP) (net.Conn, error) {
	switch p.config.PortMatching {
	case PortMatchingNone:
		return net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})

	case PortMatchingSoft:
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: clientPort})
		if err != nil {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
		}
		return conn, nil

	case PortMatchingHard:
		wantedAddr := &net.UDPAddr{IP: ip, Port: clientPort}
		if conn := p.allocated[wantedAddr.String()]; conn != nil {
			return conn, nil
		}
		return net.ListenUDP("udp4", wantedAddr)

	default:
		panic("unimplemented case")
	}
}
