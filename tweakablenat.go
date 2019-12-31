package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"go.universe.tf/natlab/config"
)

// This is the main implementation of a "very tweakable NAT", with a
// bunch of config knobs.

// natMapping is a mapping of one LAN ip:port to a WAN ip:port.
type natMapping struct {
	LANKey     UDPTuple
	LAN        UDPAddr
	WAN        UDPAddr
	ParkedPort net.Conn
	Deadline   time.Time
}

func (e *natMapping) expired() bool {
	return e.Deadline.Before(time.Now())
}

func (e *natMapping) extend(timeout time.Duration) {
	e.Deadline = time.Now().Add(d)
}

type tweakableNAT struct {
	config    config.NATConfig
	publicIPs []net.IP

	byLAN map[UDPTuple]*natMapping
	byWAN map[UDPAddr]*natMapping

	// tracks which filtering keys have been seen, and when they
	// expire. The contents of the key varies based on requested
	// filtering behavior.
	sent map[UDPTuple]time.Time

	rand rand.Rand
}

func (n *tweakableNAT) MangleOutbound(p *Packet) Verdict {
	key := n.mappingKey(p, true)
	mapping := n.byLAN[key]
	if mapping != nil && mapping.expired() {
		n.deleteMapping(mapping)
		mapping = nil
	}

	if mapping == nil {
		mapping = n.createMapping(p)
	}

	if n.config.MappingRefreshDirection == config.OutboundOnly || n.config.MappingRefreshDirection == config.Both {
		mapping.extend(config.MappingTimeout)
	}

	p.SetSrcUDPAddr(mapping.WAN)

	n.updateFilterState(p, true)

	return VerdictMangle
}

func (n *tweakableNAT) MangleInbound(p *Packet) Verdict {
	return VerdictAccept
}

func (n *tweakableNAT) createMapping(p *Packet) *natMapping {
	candidates := n.candidateIPs(n.publicIPs, n.config.AddressPooling, p.SrcUDPAddr())

	for _, ip := range candidates {
		var wanPort int
		switch n.config.PortAssignment {
		case OverloadingAssignment:
			wanPort := int(p.SrcUDPAddr().Port)
			addr := NewUDPAddr(publicIP, uint16(wanPort))
			if existingMapping := n.byWAN[addr]; mapping != nil {
				mapping := &natMapping{}
				n.deleteMapping(mapping)
			}

		case PreservingAssignment:
		}
	}
}

func (n *tweakableNAT) deleteMapping(mapping *natMapping) {
	delete(n.byLAN, mapping.LANKey)
	delete(n.byWAN, mapping.WAN)
	if mapping.ParkedPort != nil {
		mapping.ParkedPort.Close()
	}
}

func (n *tweakableNAT) candidateIPs(ips []net.IP, ap AddressPooling, lanAddr UDPAddr) []net.IP {
	switch ap {
	case config.ArbitraryPooling:
		ret = append(nil, ips...)
		n.rand.Shuffle(len(ret), func(i, j int) { ret[i], ret[j] = ret[j], ret[i] })
		return ret
	case config.PairedPooling:
		// This isn't uniform, but listen, okay?
		h := binary.LittleEndian.Uint32(lanAddr.IPv4[:])
		return []net.IP{n.publicIPs[h%len(n.publicIPs)]}
	case config.SoftPairedPooling:
		return append(n.candidateIPs(ips, config.PairedPooling, lanAddr), n.candidateIPs(ips, config.ArbitraryPooling, lanAddr)...)
	default:
		panic("Unknown pairing")
	}
}

func (n *tweakableNAT) mappingKey(p *Packet, outbound bool) UDPTuple {
	ret := p.UDPTuple()
	if !outbound {
		ret = ret.Flip()
	}

	switch n.config.MappingReuse {
	case config.EndpointIndependent:
		ret.Dst = UDPAddr{}
	case config.AddressDependent:
		ret.Dst.Port = 0
	case config.AddressAndPortDependent:
	default:
		panic("unhandled case")
	}

	return ret
}

func (n *tweakableNAT) filteringKey(p *Packet, outbound bool) UDPTuple {
	ret := p.UDPTuple()
	if !outbound {
		ret = ret.Flip()
	}

	switch n.config.FilteringBehavior {
	case config.EndpointIndependent:
		ret.Dst = UDPAddr{}
	case config.AddressDependent:
		ret.Dst.Port = 0
	case config.AddressAndPortDependent:
	default:
		panic("unhandled case")
	}
}

func (n *tweakableNAT) updateFilterState(p *Packet, outbound bool) {
	key := n.filteringKey(p, outbound)
	if outbound && n.sent[key].IsZero() {
		n.send[key] = time.Now().Add(n.config.MappingTimeout)
	}

	if (outbound && n.config.MappingRefreshDirection == config.OutboundOnly) ||
		(!outbound && n.config.MappingRefreshDirection == config.InboundOnly) ||
		n.config.MappingRefreshDirection == config.Both {
		n.sent[key] = time.Now().Add(n.config.MappingTimeout)
	}
}
