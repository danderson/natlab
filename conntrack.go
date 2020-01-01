package main

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"go.universe.tf/natlab/portmanager"
)

type TranslatorVerdict int

const (
	TranslatorVerdictAccept TranslatorVerdict = iota
	TranslatorVerdictMangle
	TranslatorVerdictDrop
)

// Translator is the top-level interface. Packets get fed in, may be
// mutated, and the verdict dictates whether the packet makes it off
// the machine.
type Translator interface {
	TranslateOutUDP(packet []byte) TranslatorVerdict
	TranslateInUDP(packet []byte) TranslatorVerdict
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
	portManager *portmanager.PortManager
}

func NewAddressAndPortDependentNAT(wanIPs []net.IP) Translator {
	cfg := &portmanager.Config{
		WANIPs: wanIPs,
	}

	return &endpointIndependentNAT{
		byOriginal:  map[UDPAddr]*ctEntry{},
		byMapped:    map[UDPAddr]*ctEntry{},
		portManager: portmanager.New(cfg),
	}
}

func (n endpointIndependentNAT) TranslateOutUDP(bs []byte) TranslatorVerdict {
	p := NewPacket(bs)
	key := p.UDPSrcAddr()

	ct := n.byOriginal[key]
	if ct != nil && ct.expired() {
		n.deleteMapping(ct)
		ct = nil
	}
	if ct == nil {
		mappedAddr, close, err := n.portManager.AllocateUDP(p.UDPSrcAddr().ToNetUDPAddr())
		if err != nil {
			log.Errorf("Failed to park port: %s", err)
			return TranslatorVerdictDrop
		}

		ct = &ctEntry{
			Original: key,
			Mapped:   FromNetUDPAddr(mappedAddr),
			Close:    close,
		}
		ct.extend()
		n.byOriginal[ct.Original] = ct
		n.byMapped[ct.Mapped] = ct
	}

	p.SetUDPSrcAddr(ct.Mapped)

	return TranslatorVerdictMangle
}

func (n endpointIndependentNAT) TranslateInUDP(bs []byte) TranslatorVerdict {
	p := NewPacket(bs)
	key := p.UDPDstAddr()

	ct := n.byMapped[key]
	if ct == nil {
		return TranslatorVerdictDrop
	}
	if ct.expired() {
		n.deleteMapping(ct)
		return TranslatorVerdictDrop
	}
	ct.extend()
	p.SetUDPDstAddr(ct.Original)
	return TranslatorVerdictMangle
}

func (n endpointIndependentNAT) deleteMapping(ct *ctEntry) {
	delete(n.byOriginal, ct.Original)
	delete(n.byMapped, ct.Mapped)
	ct.Close()
}
