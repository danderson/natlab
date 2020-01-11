package client

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Result is the raw, uninterpreted result of a probe.
type Result struct {
	MappingProbes  []*MappingProbe
	FirewallProbes *FirewallProbe
}

// MappingProbe is the outcome of a single NAT mapping discovery attempt.
type MappingProbe struct {
	Local   *net.UDPAddr
	Mapped  *net.UDPAddr
	Remote  *net.UDPAddr
	Timeout bool
}

func (p MappingProbe) key() string {
	return fmt.Sprintf("%s %s %s %s", p.Local, p.Mapped, p.Remote, p.Timeout)
}

// FirewallProbe is the outcome of a firewall state probe.
type FirewallProbe struct {
	Local    *net.UDPAddr
	Remote   *net.UDPAddr
	Received []*net.UDPAddr
}

func (r *Result) String() string {
	if len(r.MappingProbes) == 0 {
		return "No data (did the probe fail?)"
	}

	var b bytes.Buffer
	b.WriteString("Mapping probes:\n")
	for _, probe := range r.MappingProbes {
		if probe.Timeout {
			fmt.Fprintf(&b, "  %s -> ??? -> %s (timeout)\n", probe.Local, probe.Remote)
		} else {
			fmt.Fprintf(&b, "  %s -> %s -> %s\n", probe.Local, probe.Mapped, probe.Remote)
		}
	}

	if r.FirewallProbes == nil {
		fmt.Fprintf(&b, "No firewall probe data.\n")
	} else {
		fmt.Fprintf(&b, "Firewall probe with outbound traffic %s -> %s\n", r.FirewallProbes.Local, r.FirewallProbes.Remote)
		for _, addr := range r.FirewallProbes.Received {
			fmt.Fprintf(&b, "  %s\n", addr)
		}
	}

	return b.String()
}

// Anonymize replace all IP addresses in the results with generated IPs.
func (r *Result) Anonymize() {
	ips := map[string]net.IP{}
	a, b := byte(1), byte(1)

	anonymize := func(ip net.IP) net.IP {
		if ret := ips[ip.String()]; ret != nil {
			return ret
		}
		ret := net.IPv4(a, a, b, b)
		b++
		if b == 0 {
			a++
		}
		ips[ip.String()] = ret
		return ret
	}

	for _, probe := range r.MappingProbes {
		probe.Local.IP = anonymize(probe.Local.IP)
		probe.Mapped.IP = anonymize(probe.Mapped.IP)
		probe.Remote.IP = anonymize(probe.Remote.IP)
	}
	r.FirewallProbes.Local.IP = anonymize(r.FirewallProbes.Local.IP)
	r.FirewallProbes.Remote.IP = anonymize(r.FirewallProbes.Remote.IP)
	for _, addr := range r.FirewallProbes.Received {
		addr.IP = anonymize(addr.IP)
	}
}

func (r *Result) Analyze() *Analysis {
	return &Analysis{
		NoData:                     noData(r),
		MappingVariesByDestIP:      mappingVariesByDestIP(r),
		MappingVariesByDestPort:    mappingVariesByDestPort(r),
		FirewallEnforcesDestIP:     firewallEnforcesDestIP(r),
		FirewallEnforcesDestPort:   firewallEnforcesDestPort(r),
		MappingPreservesSourcePort: mappingPreservesSourcePort(r),
		MultiplePublicIPs:          multiplePublicIPs(r),
		FilteredEgress:             filteredEgress(r),
	}
}

func noData(r *Result) bool {
	if len(r.MappingProbes) == 0 {
		return true
	}
	for _, probe := range r.MappingProbes {
		if !probe.Timeout {
			return false
		}
	}
	return true
}

func mappingVariesByDestIP(r *Result) bool {
	var (
		local      string
		remoteIP   net.IP
		mappedIP   net.IP
		mappedPort int
	)

	for _, probe := range r.MappingProbes {
		if probe.Timeout {
			continue
		}
		if probe.Local.String() != local {
			local = probe.Local.String()
			remoteIP = probe.Remote.IP
			mappedIP = probe.Mapped.IP
			mappedPort = probe.Mapped.Port
			continue
		}
		if probe.Remote.IP.Equal(remoteIP) {
			continue
		}
		if !probe.Mapped.IP.Equal(mappedIP) || probe.Mapped.Port != mappedPort {
			return true
		}
	}
	return false
}

func mappingVariesByDestPort(r *Result) bool {
	var (
		local      string
		remotePort int
		mappedIP   net.IP
		mappedPort int
	)

	for _, probe := range r.MappingProbes {
		if probe.Timeout {
			continue
		}
		if probe.Local.String() != local {
			local = probe.Local.String()
			remotePort = probe.Remote.Port
			mappedIP = probe.Mapped.IP
			mappedPort = probe.Mapped.Port
			continue
		}
		if probe.Remote.Port == remotePort {
			continue
		}
		if !probe.Mapped.IP.Equal(mappedIP) || probe.Mapped.Port != mappedPort {
			return true
		}
	}
	return false
}

func mappingVariesBy(r *Result, keyFunc func(*MappingProbe) string) bool {
	var (
		key        string
		mappedIP   net.IP
		mappedPort int
	)
	for _, probe := range r.MappingProbes {
		if probe.Timeout {
			continue
		}
		if mappedIP == nil {
			key = keyFunc(probe)
			mappedIP = probe.Mapped.IP
			mappedPort = probe.Mapped.Port
			continue
		}

		if keyFunc(probe) == key {
			continue
		}
		if !mappedIP.Equal(probe.Mapped.IP) || probe.Mapped.Port != mappedPort {
			return true
		}
	}
	return false
}

func firewallEnforcesDestIP(r *Result) bool {
	if r.FirewallProbes == nil {
		return false
	}
	outIP := r.FirewallProbes.Remote.IP
	for _, recv := range r.FirewallProbes.Received {
		if !recv.IP.Equal(outIP) {
			return false
		}
	}

	return true
}

func firewallEnforcesDestPort(r *Result) bool {
	if r.FirewallProbes == nil {
		return false
	}
	outPort := r.FirewallProbes.Remote.Port
	for _, recv := range r.FirewallProbes.Received {
		if recv.Port != outPort {
			return false
		}
	}
	return true
}

func mappingPreservesSourcePort(r *Result) bool {
	total, preserved := 0, 0
	for _, probe := range r.MappingProbes {
		if probe.Timeout {
			continue
		}
		total++
		if probe.Local.Port == probe.Mapped.Port {
			preserved++
		}
	}

	// Consider the NAT port-preserving if >80% of probes have
	// preserved ports.
	return (float64(preserved) / float64(total)) >= 0.8
}

func multiplePublicIPs(r *Result) bool {
	ips := map[string]bool{}
	for _, probe := range r.MappingProbes {
		if probe.Timeout {
			continue
		}
		ips[probe.Mapped.IP.String()] = true
	}
	return len(ips) > 1
}

func filteredEgress(r *Result) []int {
	working := map[int]bool{}
	for _, probe := range r.MappingProbes {
		if !probe.Timeout {
			working[probe.Remote.Port] = true
		}
	}
	ret := []int{}
	for _, probe := range r.MappingProbes {
		if probe.Timeout && !working[probe.Remote.Port] {
			ret = append(ret, probe.Remote.Port)
			working[probe.Remote.Port] = true
		}
	}
	sort.Ints(ret)
	return ret
}

type Analysis struct {
	// There is no data to analyze.
	NoData bool
	// Assigned public ip:port depends on the destination IP.
	MappingVariesByDestIP bool
	// Assigned public ip:port depends on the destination port.
	MappingVariesByDestPort bool
	// Firewall requires outbound traffic to an IP before allowing
	// inbound traffic from that IP.
	FirewallEnforcesDestIP bool
	// Firewall requires outbound traffic to a port before allowing
	// inbound traffic from that port.
	FirewallEnforcesDestPort bool
	// Assigned public port tries to be the same as the LAN port.
	MappingPreservesSourcePort bool
	// Observed multiple assigned public IPs.
	MultiplePublicIPs bool
	// Outbound probes that didn't see a response, indicating outbound
	// filtering.
	FilteredEgress []int
}

func (a *Analysis) Narrative() string {
	if a.NoData {
		return "Probing got no useful data at all. Either the probe servers are down, or extremely strict UDP filtering is in place on your LAN."
	}
	ret := []string{}

	switch {
	case a.MappingVariesByDestPort && a.MappingVariesByDestIP:
		ret = append(ret, `NAT allocates a new ip:port for every unique 5-tuple (protocol, source ip, source port, destination ip, destination port).
  This makes NAT traversal more difficult.`)
	case a.MappingVariesByDestIP:
		ret = append(ret, `NAT allocates a new ip:port for every unique IP 4-tuple (protocol, source ip, source port, destination ip).
  This makes NAT traversal more difficult.`)
	case a.MappingVariesByDestPort:
		ret = append(ret, `NAT allocates a new ip:port for every unique port 4-tuple (protocol, source ip, source port, destination port).
  This is unusual!
  This makes NAT traversal more difficult.`)
	default:
		ret = append(ret, `NAT allocates a new ip:port for every unique 3-tuple (protocol, source ip, source ports).
  This is best practice for NAT devices.`)
	}

	switch {
	case a.FirewallEnforcesDestIP && a.FirewallEnforcesDestPort:
		ret = append(ret, `Firewall requires outbound traffic to an ip:port before allowing inbound traffic from that ip:port.
  This is common practice for NAT gateways.
  This makes NAT traversal more difficult.`)
	case a.FirewallEnforcesDestIP:
		ret = append(ret, `Firewall requires outbound traffic to an ip before allowing inbound traffic from that ip, but the ports don't have to match.
  This makes NAT traversal more difficult.`)
	case a.FirewallEnforcesDestPort:
		ret = append(ret, `Firewall requires outbound traffic to a port before allowing inbound traffic from that port, but the IPs don't have to match.
  This is unusual!
  This makes NAT traversal more difficult.`)
	default:
		ret = append(ret, `Firewall allows inbound traffic from any source, with no prerequisites.
  This is best practice for "traversal-friendly" NAT devices.`)
	}

	if a.MappingPreservesSourcePort {
		ret = append(ret, `NAT seems to try and make the public port number match the LAN port number.`)
	} else {
		ret = append(ret, `NAT seems to randomize the public port when allocating a new mapping.`)
	}

	if a.MultiplePublicIPs {
		ret = append(ret, `NAT seems to use different public IPs for different mappings.
  This makes NAT traversal more difficult.`)
	} else {
		ret = append(ret, `NAT seems to only use one public IP for this client.`)
	}

	return strings.Join(ret, "\n")
}
