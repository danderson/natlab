package main

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"go.universe.tf/natlab/portmanager"
)

type Verdict int

const (
	VerdictAccept Verdict = iota
	VerdictMangle
	VerdictDrop
)

type Conntrack interface {
	MangleOutbound(p *Packet) Verdict
	MangleInbound(p *Packet) Verdict
}

type ctEntry struct {
	Original UDPAddr
	Mapped   UDPAddr
	Close    func()
	Deadline time.Time
}

func (e *ctEntry) expired() bool {
	return e.Deadline.Before(time.Now())
}

func (e *ctEntry) extend() {
	e.Deadline = time.Now().Add(120 * time.Second)
}

type endpointIndependentNAT struct {
	publicIP net.IP
	// byOriginal matches on outbound packet 4-tuples.
	byOriginal map[UDPAddr]*ctEntry
	// byMapped matches on inbound packet 4-tuples
	byMapped    map[UDPAddr]*ctEntry
	portManager portmanager.PortManager
}

func NewAddressAndPortDependentNAT(publicIP net.IP) Conntrack {
	return &endpointIndependentNAT{
		publicIP:    publicIP,
		byOriginal:  map[UDPAddr]*ctEntry{},
		byMapped:    map[UDPAddr]*ctEntry{},
		portManager: portmanager.New([]net.IP{publicIP}),
	}
}

func (n endpointIndependentNAT) MangleOutbound(p *Packet) Verdict {
	key := p.UDPSrcAddr()

	ct := n.byOriginal[key]
	if ct != nil && ct.expired() {
		n.deleteMapping(ct)
		ct = nil
	}
	if ct == nil {
		mappedAddr, close, err := n.portManager.Allocate(p.UDPSrcAddr().ToNetUDPAddr())
		if err != nil {
			log.Errorf("Failed to park port: %s", err)
			return VerdictDrop
		}

		ct = &ctEntry{
			Original: key,
			Mapped:   FromNetUDPAddr(mappedAddr),
			Close:    close,
		}
		copy(ct.Mapped.IPv4[:], n.publicIP)
		ct.extend()
		n.byOriginal[ct.Original] = ct
		n.byMapped[ct.Mapped] = ct
	}

	p.SetUDPSrcAddr(ct.Mapped)

	return VerdictMangle
}

func (n endpointIndependentNAT) MangleInbound(p *Packet) Verdict {
	key := p.UDPDstAddr()

	ct := n.byMapped[key]
	if ct == nil {
		return VerdictDrop
	}
	if ct.expired() {
		n.deleteMapping(ct)
		return VerdictDrop
	}
	ct.extend()
	p.SetUDPDstAddr(ct.Original)
	return VerdictMangle
}

func (n endpointIndependentNAT) deleteMapping(ct *ctEntry) {
	delete(n.byOriginal, ct.Original)
	delete(n.byMapped, ct.Mapped)
	ct.Close()
}
