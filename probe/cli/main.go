package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

func main() {
	addrs, err := resolveProbeAddrs()
	if err != nil {
		logrus.Fatalf("Getting probe server addrs: %s", err)
	}
	logrus.Infof("Characterizing NAT, using %s", addrs)

	a := &Analysis{
		Servers:  *addrs,
		Received: map[string]bool{},
	}

	// Step one: what parts of the packet tuple influence NAT mapping creation?
	if err = mappingBehavior(addrs, a); err != nil {
		logrus.Fatalf("Determining mapping behavior: %s", err)
	}
	if err = firewallBehavior(addrs, a); err != nil {
		logrus.Fatalf("Determining firewall behavior: %s", err)
	}

	logrus.Info(a)
}

type Analysis struct {
	Servers  EightTuple
	Mapping  EightTuple
	Received map[string]bool
}

func (a Analysis) MappingBehavior() string {
	// TODO: should account for randomized IP pairing, and see if we
	// can still get some port determinism.
	switch {
	case udpAddrEqual(a.Mapping.A1, a.Mapping.A2) && udpAddrEqual(a.Mapping.A1, a.Mapping.B1) && udpAddrEqual(a.Mapping.A1, a.Mapping.B2):
		return "src ip:port"
	case udpAddrEqual(a.Mapping.A1, a.Mapping.A2) && udpAddrEqual(a.Mapping.B1, a.Mapping.B2):
		return "src ip:port and dst ip"
	default:
		return "src ip:port and dst ip:port"
	}
}

func (a Analysis) IPPairing() string {
	if !a.Mapping.A1.IP.Equal(a.Mapping.A2.IP) ||
		!a.Mapping.A1.IP.Equal(a.Mapping.B1.IP) ||
		!a.Mapping.A1.IP.Equal(a.Mapping.B2.IP) {
		return "arbitrary"
	}
	return "deterministic"
}

func (a Analysis) FirewallBehavior() string {
	a1 := a.Received[a.Servers.A1.String()]
	a2 := a.Received[a.Servers.A2.String()]
	b1 := a.Received[a.Servers.B1.String()]
	b2 := a.Received[a.Servers.B2.String()]

	switch {
	case a1 && a2 && b1 && b2:
		return "src ip:port"
	case a1 && a2 && !b1 && !b2:
		return "src ip:port and dst ip"
	case a1 && !a2 && !b1 && !b2:
		return "src ip:port and dst ip:port"
	default:
		return "(unclear, see full data)"
	}
}

func (a Analysis) String() string {
	return fmt.Sprintf(`
  Mapping key : %s
  Firewall key: %s
  Public IP is: %s`, a.MappingBehavior(), a.FirewallBehavior(), a.IPPairing())
}

func firewallBehavior(probeAddrs *EightTuple, a *Analysis) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("creating UDP socket for probing: %s", err)
	}
	defer conn.Close()

	go spam(conn, probeAddrs.A1)

	var (
		buf      [1500]byte
		deadline = time.Now().Add(3 * time.Second)
	)

	for time.Now().Before(deadline) {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			return err
		}

		if n != 18 {
			logrus.Infof("Received wrong size packet (%d bytes)", n)
			continue
		}

		a.Received[addr.String()] = true
	}

	return nil
}

func spam(conn *net.UDPConn, addr *net.UDPAddr) {
	var req [180]byte
	key := byte(0)
	for {
		req[0] = 0
		if _, err := conn.WriteToUDP(req[:], addr); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)

		req[0] = key
		key++
		if _, err := conn.WriteToUDP(req[:], addr); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func mappingBehavior(probeAddrs *EightTuple, a *Analysis) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("creating UDP socket for probing: %s", err)
	}
	defer conn.Close()

	a.Mapping.A1, err = mapping(conn, probeAddrs.A1)
	if err != nil {
		logrus.Fatal(err)
	}
	a.Mapping.A2, err = mapping(conn, probeAddrs.A2)
	if err != nil {
		logrus.Fatal(err)
	}
	a.Mapping.B1, err = mapping(conn, probeAddrs.B1)
	if err != nil {
		logrus.Fatal(err)
	}
	a.Mapping.B2, err = mapping(conn, probeAddrs.B2)
	if err != nil {
		logrus.Fatal(err)
	}

	// var (
	// 	sensitivity = TupleSensitivityNone
	// 	variance    = AddressVariance(false)
	// )

	// if !a.Mapping.A1.IP.Equal(a.Mapping.A2.IP) ||
	// 	!a.Mapping.A1.IP.Equal(a.Mapping.B1.IP) ||
	// 	!a.Mapping.A1.IP.Equal(a.Mapping.B2.IP) {
	// 	// There is variance in the mapped IP address, the NAT gateway
	// 	// isn't doing source address pairing.
	// 	variance = true
	// }

	// switch {
	// case udpAddrEqual(a.Mapping.A1, a.Mapping.A2) && udpAddrEqual(a.Mapping.A1, a.Mapping.B1) && udpAddrEqual(a.Mapping.A1, a.Mapping.B2):
	// 	sensitivity = TupleSensitivityNone
	// case udpAddrEqual(a.Mapping.A1, a.Mapping.A2) && udpAddrEqual(a.Mapping.B1, a.Mapping.B2):
	// 	sensitivity = TupleSensitivityAddress
	// default:
	// 	sensitivity = TupleSensitivityAddressPort
	// }

	return nil
}

func mapping(conn *net.UDPConn, dest *net.UDPAddr) (*net.UDPAddr, error) {
	var req [180]byte

	attempts := 5
retryloop:
	for i := 0; i < attempts; i++ {
		if _, err := conn.WriteToUDP(req[:], dest); err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, addr, err := conn.ReadFromUDP(req[:])
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue retryloop
				}
				return nil, err
			}
			if addr.String() != dest.String() {
				logrus.Infof("Received packet from unexpected address %s (want %s)", addr, dest)
				continue
			}
			if n != 18 {
				logrus.Infof("Received wrong size packet (%d bytes)", n)
				continue
			}

			ret := &net.UDPAddr{
				IP:   make(net.IP, 16),
				Port: int(binary.BigEndian.Uint16(req[16:18])),
			}
			copy(ret.IP, req[:16])
			return ret, nil
		}
	}

	return nil, fmt.Errorf("No mapping response from %s after %d attempts", dest, attempts)
}

type EightTuple struct {
	A1 *net.UDPAddr
	A2 *net.UDPAddr
	B1 *net.UDPAddr
	B2 *net.UDPAddr
}

func (a EightTuple) String() string {
	return fmt.Sprintf("{%s,%s}:{%d,%d}", a.A1.IP, a.B1.IP, a.A1.Port, a.A2.Port)
}

func (a EightTuple) List() []*net.UDPAddr {
	return []*net.UDPAddr{a.A1, a.A2, a.B1, a.B2}
}

func resolveProbeAddrs() (*EightTuple, error) {
	ret := &EightTuple{}

	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), "natprobe1.universe.tf.")
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.IP.To4() == nil {
			continue
		}
		ret.A1 = &net.UDPAddr{IP: addr.IP.To4(), Port: 443}
		ret.A2 = &net.UDPAddr{IP: addr.IP.To4(), Port: 4001}
	}

	addrs, err = net.DefaultResolver.LookupIPAddr(context.Background(), "natprobe2.universe.tf.")
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.IP.To4() == nil {
			continue
		}
		ret.B1 = &net.UDPAddr{IP: addr.IP.To4(), Port: 443}
		ret.B2 = &net.UDPAddr{IP: addr.IP.To4(), Port: 4001}
	}

	return ret, nil
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}
