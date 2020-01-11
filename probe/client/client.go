package client

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

// Options configures the probe.
type Options struct {
	ServerAddrs []string
	Ports       []int

	ResolveDuration time.Duration

	MappingDuration         time.Duration
	MappingTransmitInterval time.Duration
	MappingSockets          int

	FirewallDuration         time.Duration
	FirewallTransmitInterval time.Duration
}

func (o *Options) addDefaults() {
	if len(o.ServerAddrs) == 0 {
		o.ServerAddrs = []string{"natprobe1.universe.tf.", "natprobe2.universe.tf."}
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{
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
		}
	}
	if o.ResolveDuration == 0 {
		o.ResolveDuration = 3 * time.Second
	}
	if o.MappingDuration == 0 {
		o.MappingDuration = 3 * time.Second
	}
	if o.MappingTransmitInterval == 0 {
		o.MappingTransmitInterval = 200 * time.Millisecond
	}
	if o.MappingSockets == 0 {
		o.MappingSockets = 3
	}
	if o.FirewallDuration == 0 {
		o.FirewallDuration = 3 * time.Second
	}
	if o.FirewallTransmitInterval == 0 {
		o.FirewallTransmitInterval = 50 * time.Millisecond
	}
}

// Probe probes the NAT behavior between the local machine and remote probe servers.
func Probe(ctx context.Context, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{}
	}
	opts.addDefaults()

	// Assemble destination UDP addresses.
	ips, err := resolveServerAddrs(ctx, opts.ServerAddrs, opts.ResolveDuration)
	if err != nil {
		return nil, err
	}
	dests := dests(ips, opts.Ports)

	// Probe the NAT for its mapping behavior.
	probes, err := probeMapping(ctx, dests, opts.MappingSockets, opts.MappingDuration, opts.MappingTransmitInterval)
	if err != nil {
		return nil, err
	}

	// If we got any successful mapping response, use that address for
	// firewall probing.
	var firewall *FirewallProbe
	for _, probe := range probes {
		if probe.Timeout {
			continue
		}
		firewall, err = probeFirewall(ctx, probe.Remote, opts.FirewallDuration, opts.FirewallTransmitInterval)
		if err != nil {
			return nil, err
		}
		break
	}

	return &Result{
		MappingProbes:  probes,
		FirewallProbes: firewall,
	}, nil
}

func dests(ips []net.IP, ports []int) []*net.UDPAddr {
	var ret []*net.UDPAddr
	for _, ip := range ips {
		for _, port := range ports {
			ret = append(ret, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	return ret
}

func probeFirewall(ctx context.Context, dest *net.UDPAddr, duration time.Duration, txInterval time.Duration) (*FirewallProbe, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		panic("deadline unexpectedly not set in context")
	}
	if err = conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	go transmit(ctx, conn, []*net.UDPAddr{dest}, txInterval, true)

	var (
		ret = FirewallProbe{
			Local:  copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
			Remote: copyUDPAddr(dest),
		}
		buf  [1500]byte
		seen = map[string]bool{}
	)
	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return &ret, nil
			}
			return nil, err
		}

		if n != 18 {
			continue
		}

		if !seen[addr.String()] {
			ret.Received = append(ret.Received, addr)
			seen[addr.String()] = true
		}
	}
}

func probeMapping(ctx context.Context, dests []*net.UDPAddr, sockets int, duration time.Duration, txInterval time.Duration) ([]*MappingProbe, error) {
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	type result struct {
		probes []*MappingProbe
		err    error
	}

	done := make(chan result)

	for i := 0; i < sockets; i++ {
		go func() {
			res, err := probeOneMapping(ctx, dests, txInterval)
			done <- result{probes: res, err: err}
		}()
	}

	var ret []*MappingProbe
	for i := 0; i < sockets; i++ {
		res := <-done
		if res.err != nil {
			return nil, res.err
		}
		ret = append(ret, res.probes...)
	}

	return ret, nil
}

func probeOneMapping(ctx context.Context, dests []*net.UDPAddr, txInterval time.Duration) ([]*MappingProbe, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}

	var (
		seenByDest = map[string]bool{}
		ret        = []*MappingProbe{}
	)

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		conn.Close()

		for _, dest := range dests {
			if !seenByDest[dest.String()] {
				ret = append(ret, &MappingProbe{
					Local:   copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
					Remote:  copyUDPAddr(dest),
					Timeout: true,
				})
			}
		}
	}()

	deadline, ok := ctx.Deadline()
	if !ok {
		panic("deadline unexpectedly not set in context")
	}
	if err = conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	go transmit(ctx, conn, dests, txInterval, false)

	var (
		buf  [1500]byte
		seen = map[string]bool{}
	)

	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return ret, nil
			}
			return nil, err
		}

		if n != 18 {
			continue
		}

		mapped := &net.UDPAddr{
			IP:   net.IP(buf[:16]),
			Port: int(binary.BigEndian.Uint16(buf[16:18])),
		}

		probe := &MappingProbe{
			Local:  copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
			Mapped: copyUDPAddr(mapped),
			Remote: copyUDPAddr(addr),
		}
		if !seen[probe.key()] {
			ret = append(ret, probe)
			seen[probe.key()] = true
			seenByDest[addr.String()] = true
		}
	}
}

func transmit(ctx context.Context, conn *net.UDPConn, dests []*net.UDPAddr, txInterval time.Duration, cycle bool) {
	var req [180]byte
	done := make(chan struct{})
	for _, dest := range dests {
		go func(dest *net.UDPAddr) {
			defer func() { done <- struct{}{} }()

			for {
				if cycle {
					req[0] = (req[0] + 1) % 4
				}
				if _, err := conn.WriteToUDP(req[:], dest); err != nil {
					// TODO: log, somehow...
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(txInterval):
				}
			}
		}(dest)
	}

	for range dests {
		<-done
	}
}

func resolveServerAddrs(ctx context.Context, addrs []string, timeout time.Duration) (ips []net.IP, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, addr := range addrs {
		results, err := net.DefaultResolver.LookupIPAddr(ctx, addr)
		if err != nil {
			return nil, err
		}

		for _, result := range results {
			ip := result.IP.To4()
			if ip == nil {
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func copyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), a.IP...),
		Port: a.Port,
	}
}
