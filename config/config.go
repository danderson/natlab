package config

import "time"

type EndpointDependence int
type AddressPooling int
type PortAssignment int
type MappingRefreshDirection int
type HairpinningBehavior int

const (
	EndpointIndependent EndpointDependence = iota
	AddressDependent
	AddressAndPortDependent

	ArbitraryPooling AddressPooling = iota
	PairedPooling
	SoftPairedPooling

	OverloadingAssignment PortAssignment = iota
	PreservingAssignment
	ArbitraryAssignment

	OutboundOnly MappingRefreshDirection = iota
	InboundOnly
	Both

	NoHairpinning HairpinningBehavior = iota
	InternalSource
	ExternalSource
)

type NATConfig struct {
	MappingReuse            EndpointDependence
	MappingTimeout          time.Duration
	MappingRefreshDirection MappingRefreshDirection
	FilteringBehavior       EndpointDependence
	PortAssignment          PortAssignment
	AddressPooling          AddressPooling
}
