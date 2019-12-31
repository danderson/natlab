package main

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
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
	Original   UDPTuple
	Mapped     UDPTuple
	ParkedPort net.Conn
	Deadline   time.Time
}

func (e *ctEntry) expired() bool {
	return e.Deadline.Before(time.Now())
}

func (e *ctEntry) extend() {
	e.Deadline = time.Now().Add(120 * time.Second)
}

type ConntrackKey interface {
	OutboundKey(p *Packet) UDPTuple
	InboundKey(p *Packet) UDPTuple
}

type addressAndPortDependentNAT struct {
	publicIP net.IP
	// byOriginal matches on outbound packet 4-tuples.
	byOriginal map[UDPTuple]*ctEntry
	// byMapped matches on inbound packet 4-tuples
	byMapped map[UDPTuple]*ctEntry
}

func NewAddressAndPortDependentNAT(publicIP net.IP) Conntrack {
	return &addressAndPortDependentNAT{
		publicIP:   publicIP,
		byOriginal: map[UDPTuple]*ctEntry{},
		byMapped:   map[UDPTuple]*ctEntry{},
	}
}

func (n addressAndPortDependentNAT) MangleOutbound(p *Packet) Verdict {
	key := p.UDPTuple()

	ct := n.byOriginal[key]
	if ct != nil && ct.expired() {
		n.deleteMapping(ct)
		ct = nil
	}
	if ct == nil {
		parked, port, err := parkPort(n.publicIP)
		if err != nil {
			log.Errorf("Failed to park port: %s", err)
			return VerdictDrop
		}

		ct = &ctEntry{
			Original: key,
			Mapped: UDPTuple{
				Src: UDPAddr{
					Port: port,
				},
				Dst: key.Dst,
			},
			ParkedPort: parked,
		}
		copy(ct.Mapped.Src.IPv4[:], n.publicIP)
		ct.extend()
		n.byOriginal[key] = ct
		n.byMapped[ct.Mapped.Flip()] = ct
	}

	p.SetUDPTuple(ct.Mapped)

	return VerdictMangle
}

func (n addressAndPortDependentNAT) MangleInbound(p *Packet) Verdict {
	key := p.UDPTuple()

	ct := n.byMapped[key]
	if ct == nil {
		return VerdictDrop
	}
	if ct.expired() {
		n.deleteMapping(ct)
		return VerdictDrop
	}
	ct.extend()
	p.SetUDPTuple(ct.Original.Flip())
	return VerdictMangle
}

func (n addressAndPortDependentNAT) deleteMapping(ct *ctEntry) {
	delete(n.byOriginal, ct.Original)
	delete(n.byMapped, ct.Mapped.Flip())
	ct.ParkedPort.Close()
}

func parkPort(srcIP net.IP) (net.Conn, uint16, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: srcIP})
	if err != nil {
		return nil, 0, err
	}

	return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port), nil
}
