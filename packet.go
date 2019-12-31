package main

import (
	"encoding/binary"
)

type UDPAddr struct {
	IPv4 [4]byte
	Port uint16
}

type UDPTuple struct {
	Src UDPAddr
	Dst UDPAddr
}

func (u UDPTuple) Flip() UDPTuple {
	return UDPTuple{
		Src: u.Dst,
		Dst: u.Src,
	}
}

type Packet struct {
	bytes []byte
	// FIXME: support for mangling ICMP packets that have UDP4 error payloads
}

// NewPacket returns a Packet manipulator around the given bytes, if
// the bytes represent a packet type we know how to mangle.
func NewPacket(bs []byte) *Packet {
	ret := &Packet{
		bytes: bs,
	}
	if !ret.isUDP4() {
		return nil
	}
	return ret
}

func (p Packet) isUDP4() bool {
	return p.isIPv4() && p.l4proto() == 17
}

func (p Packet) isIPv4() bool {
	return p.bytes[0]>>4 == 4
}

func (p Packet) l4proto() byte {
	return p.bytes[9]
}

func (p Packet) UDPTuple() UDPTuple {
	if !p.isUDP4() {
		panic("not UDP4")
	}

	ret := UDPTuple{
		Src: UDPAddr{
			Port: binary.BigEndian.Uint16(p.udpSrcPort()),
		},
		Dst: UDPAddr{
			Port: binary.BigEndian.Uint16(p.udpDstPort()),
		},
	}
	copy(ret.Src.IPv4[:], p.bytes[12:16])
	copy(ret.Dst.IPv4[:], p.bytes[16:20])
	return ret
}

func (p Packet) SetUDPTuple(u UDPTuple) {
	if !p.isUDP4() {
		panic("not UDP4")
	}

	copy(p.bytes[12:16], u.Src.IPv4[:])
	copy(p.bytes[16:20], u.Dst.IPv4[:])
	binary.BigEndian.PutUint16(p.udpSrcPort(), u.Src.Port)
	binary.BigEndian.PutUint16(p.udpDstPort(), u.Dst.Port)
	p.recomputeChecksum()
}

func (p Packet) udpSrcPort() []byte {
	return p.bytes[p.ipHdrLen() : p.ipHdrLen()+2]
}

func (p Packet) udpDstPort() []byte {
	return p.bytes[p.ipHdrLen()+2 : p.ipHdrLen()+4]
}

func (p Packet) ipHdrLen() int {
	return int(p.bytes[0]&0xF) * 4
}

func (p Packet) recomputeChecksum() {
	var sum uint32

	for i := 0; i < p.ipHdrLen(); i += 2 {
		if i == 10 {
			// Skip the checksum field
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(p.bytes[i : i+2]))
	}
	// In one's complement, each carry should increment the sum.
	sum = (sum & 0xFFFF) + (sum >> 16)
	// ... and in some cases, carry increments cause another carry.
	sum = (sum & 0xFFFF) + (sum >> 16)
	binary.BigEndian.PutUint16(p.bytes[10:12], ^uint16(sum))
}
