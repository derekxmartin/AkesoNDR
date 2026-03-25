// Package common defines the shared types used across AkesoNDR components.
package common

import (
	"net"
	"time"
)

// FlowKey uniquely identifies a network session by its 5-tuple.
type FlowKey struct {
	SrcIP    net.IP `json:"src_ip"`
	DstIP    net.IP `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"` // 6=TCP, 17=UDP, 1=ICMP
}

// NetworkDirection classifies traffic flow relative to the monitored network.
type NetworkDirection string

const (
	DirectionInternal NetworkDirection = "internal"
	DirectionExternal NetworkDirection = "external"
	DirectionInbound  NetworkDirection = "inbound"
	DirectionOutbound NetworkDirection = "outbound"
	DirectionUnknown  NetworkDirection = "unknown"
)

// TransportProtocol is the L4 transport.
type TransportProtocol string

const (
	TransportTCP  TransportProtocol = "tcp"
	TransportUDP  TransportProtocol = "udp"
	TransportICMP TransportProtocol = "icmp"
)

// Severity represents a 1-10 severity scale.
type Severity int

// Quadrant classifies a host by combined threat × certainty.
type Quadrant string

const (
	QuadrantLow      Quadrant = "low"
	QuadrantMedium   Quadrant = "medium"
	QuadrantHigh     Quadrant = "high"
	QuadrantCritical Quadrant = "critical"
)

// MITRETechnique maps a detection to the ATT&CK framework.
type MITRETechnique struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	TacticID      string `json:"tactic_id"`
	TacticName    string `json:"tactic_name"`
}

// Timestamp is an alias for convenience.
type Timestamp = time.Time
