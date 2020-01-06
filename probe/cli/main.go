package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var ports = flag.String("ports", "", "target ports to probe")

func main() {
	p := &Prober{
		firewall: &FirewallProbe{},
	}

	if err := p.probeNAT(); err != nil {
		logrus.Fatalf("NAT probing failed: %s", err)
	}

	if err := p.probeFirewall(); err != nil {
		logrus.Fatalf("Firewall probing failed: %s", err)
	}

	logrus.Infof("Recorded %d mapping results", len(p.mapping))
	for _, probe := range p.mapping {
		logrus.Info(probe.String())
	}

	logrus.Infof("Firewall probing received packets from %d addrs", len(p.firewall.Received))
}

type MappingProbe struct {
	// The local address from which we probed.
	Local *net.UDPAddr
	// The mapped address assigned by NAT
	Mapped *net.UDPAddr
	// The remote mapping server endpoint we used.
	Remote *net.UDPAddr
	// Did the probe time out? If so, Mapped will be nil.
	Timeout bool
}

func (p MappingProbe) key() string {
	return fmt.Sprintf("%s %s %s %s", p.Local, p.Mapped, p.Remote, p.Timeout)
}

func (p MappingProbe) String() string {
	if p.Timeout {
		return fmt.Sprintf("%s -> ??? -> %s (timeout)", p.Local, p.Remote)
	}
	return fmt.Sprintf("%s -> %s -> %s", p.Local, p.Mapped, p.Remote)
}

type FirewallProbe struct {
	// The local address from which we probed
	Local *net.UDPAddr
	// The remote mapping server to which we were transmitting.
	Remote *net.UDPAddr
	// Remote addresses from which we received responses.
	Received []*net.UDPAddr
}

type Prober struct {
	mu       sync.Mutex
	mapping  []*MappingProbe
	firewall *FirewallProbe
}

func (p *Prober) probeNAT() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})

	destIPs, err := probeIPs()
	if err != nil {
		return err
	}
	destPorts, err := probePorts()
	if err != nil {
		return err
	}

	logrus.Infof("Probing NAT mapping behavior using %d IPs and %d ports", len(destIPs), len(destPorts))

	dests := []*net.UDPAddr{}
	for _, ip := range destIPs {
		for _, port := range destPorts {
			dests = append(dests, &net.UDPAddr{IP: ip, Port: port})
		}
	}

	for i := 0; i < 3; i++ {
		go func() {
			p.probeOneNAT(ctx, dests)
			done <- struct{}{}
		}()
	}

	<-ctx.Done()

	// Wait for each conn prober to shut down.
	for i := 0; i < 3; i++ {
		<-done
	}
	return nil
}

func (p *Prober) probeFirewall() error {
	p.mu.Lock()
	var dest *net.UDPAddr
	for _, probe := range p.mapping {
		if probe.Timeout {
			continue
		}
		dest = probe.Remote
		break
	}
	if dest == nil {
		return errors.New("couldn't find a working NAT target to probe with")
	}
	p.mu.Unlock()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}

	var (
		buf  [1500]byte
		seen = map[string]bool{}
		done = make(chan struct{})
	)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer func() {
		cancel()
		<-done
		conn.Close()
	}()

	go func() {
		transmit(ctx, conn, []*net.UDPAddr{dest}, true)
		done <- struct{}{}
	}()

	p.mu.Lock()
	p.firewall.Local = conn.LocalAddr().(*net.UDPAddr)
	p.firewall.Remote = dest
	p.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}

		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			return err
		}

		if n != 18 {
			continue
		}

		if !seen[addr.String()] {
			p.mu.Lock()
			p.firewall.Received = append(p.firewall.Received, addr)
			p.mu.Unlock()
		}
		seen[addr.String()] = true
	}
}

func (p *Prober) probeOneNAT(ctx context.Context, dests []*net.UDPAddr) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}

	var (
		buf        [1500]byte
		seen       = map[string]bool{}
		seenByDest = map[string]bool{}
		done       = make(chan struct{})
	)

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		<-done
		conn.Close()

		p.mu.Lock()
		for _, dest := range dests {
			if !seenByDest[dest.String()] {
				p.mapping = append(p.mapping, &MappingProbe{
					Local:   conn.LocalAddr().(*net.UDPAddr),
					Remote:  dest,
					Timeout: true,
				})
			}
		}
		p.mu.Unlock()
	}()

	go func() {
		transmit(ctx, conn, dests, false)
		done <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}

		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			return err
		}

		if n != 18 {
			continue
		}

		mapped := &net.UDPAddr{
			IP:   net.IP(buf[:16]),
			Port: int(binary.BigEndian.Uint16(buf[16:18])),
		}

		probe := &MappingProbe{
			Local:  conn.LocalAddr().(*net.UDPAddr),
			Mapped: mapped,
			Remote: addr,
		}
		if !seen[probe.key()] {
			p.mu.Lock()
			p.mapping = append(p.mapping, probe)
			p.mu.Unlock()
		}
		seen[probe.key()] = true
		seenByDest[addr.String()] = true
	}
}

func transmit(ctx context.Context, conn *net.UDPConn, dests []*net.UDPAddr, cycle bool) {
	var req [180]byte
	done := make(chan struct{})
	for _, dest := range dests {
		go func(dest *net.UDPAddr) {
			defer func() { done <- struct{}{} }()

			delay := 200 * time.Millisecond
			if cycle {
				delay = 50 * time.Millisecond
			}

			for {
				// Cycle the vary bits on the request to vary response
				// address, response port, or both.
				if cycle {
					switch {
					case req[0] == 0 && req[1] == 0:
						req[1] = 1
					case req[0] == 0 && req[1] == 1:
						req[0] = 1
					case req[0] == 1 && req[1] == 1:
						req[1] = 0
					case req[0] == 1 && req[1] == 0:
						req[0] = 0
					}
				}

				if _, err := conn.WriteToUDP(req[:], dest); err != nil {
					logrus.Warnf("Error sending to %s: %s", dest, err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
		}(dest)
	}

	<-ctx.Done()
	for range dests {
		<-done
	}
}

func probeIPs() ([]net.IP, error) {
	var ret []net.IP

	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), "natprobe1.universe.tf.")
	if err != nil {
		return nil, err
	}

	addrs2, err := net.DefaultResolver.LookupIPAddr(context.Background(), "natprobe2.universe.tf.")
	if err != nil {
		return nil, err
	}

	for _, addr := range append(addrs, addrs2...) {
		if addr.IP.To4() == nil {
			continue
		}
		ret = append(ret, addr.IP.To4())
	}

	return ret, nil
}

func probePorts() ([]int, error) {
	if *ports == "" {
		// This is a default list of ports, which tries to maximize
		// the chances of getting any kind of traffic through even a
		// NAT that blocks generic outbound UDP.
		return []int{
			// One more random port in the IANA "Dynamic Ports"
			// range. Along with the other ports below, we cover each
			// of the 3 IANA port ranges ("Well Known", "Registered",
			// "Dynamic") with at least 2 ports each.
			60000,

			// QUIC, likely to be open even on restrictive
			// networks. These are also two ports in the IANA "Well
			// Known Ports" range.
			80, 443,

			// VPN protocols. Likely to be open on restrictive, but
			// business-friendly networks.

			// IKE (IPSec)
			500,
			// L2TP over UDP
			1701,
			// IPSec ESP over UDP
			4500,
			// PPTP
			1723,
			// OpenVPN
			1194,
			// Wireguard
			51820,

			// VOIP protocols. Likely to be open on restrictive, but
			// business-friendly networks.

			// STUN
			3478,
			// SIP cleartext
			5060,
			// SIP TLS
			5061,
		}, nil
	}

	ret := []int{}
	for _, f := range strings.Split(*ports, ",") {
		i, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse port number %q: %s", f, err)
		}
		ret = append(ret, i)
	}
	return ret, nil
}

//
//
//
//
//
//

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
		ret.A2 = &net.UDPAddr{IP: addr.IP.To4(), Port: 8443}
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
		ret.B2 = &net.UDPAddr{IP: addr.IP.To4(), Port: 8443}
	}

	return ret, nil
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}
