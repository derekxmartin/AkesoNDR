package common

import "time"

// ConnState represents the TCP connection state using Zeek's conn_state model.
type ConnState string

const (
	ConnStateS0   ConnState = "S0"   // SYN sent, no reply
	ConnStateS1   ConnState = "S1"   // SYN-ACK seen, connection established
	ConnStateSF   ConnState = "SF"   // Normal close (FIN handshake)
	ConnStateREJ  ConnState = "REJ"  // Connection rejected (RST to SYN)
	ConnStateRSTO ConnState = "RSTO" // Originator sent RST
	ConnStateRSTR ConnState = "RSTR" // Responder sent RST
	ConnStateS2   ConnState = "S2"   // Established, close attempt by originator (FIN sent)
	ConnStateS3   ConnState = "S3"   // Established, close attempt by responder (FIN sent)
	ConnStateOTH  ConnState = "OTH"  // No SYN seen, midstream pickup
)

// SessionMeta holds connection-level metadata for a single network session.
// Populated by the connection tracker (akeso-sessions) for every TCP/UDP flow.
type SessionMeta struct {
	// Identity
	ID          string  `json:"id"`
	CommunityID string  `json:"community_id"`
	Flow        FlowKey `json:"flow"`

	// Transport
	Transport TransportProtocol `json:"transport"`
	Service   string            `json:"service,omitempty"` // Detected app protocol: "dns", "http", "tls", etc.
	Direction NetworkDirection  `json:"direction"`

	// Timing
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time,omitempty"`
	Duration  time.Duration `json:"duration"`

	// State (TCP)
	ConnState ConnState `json:"conn_state"`

	// Metrics — originator (src → dst)
	OrigBytes   uint64 `json:"orig_bytes"`
	OrigPackets uint64 `json:"orig_packets"`

	// Metrics — responder (dst → src)
	RespBytes   uint64 `json:"resp_bytes"`
	RespPackets uint64 `json:"resp_packets"`

	// Layer 2
	VLANID  uint16 `json:"vlan_id,omitempty"`
	SrcMAC  string `json:"src_mac,omitempty"`
	DstMAC  string `json:"dst_mac,omitempty"`

	// TCP fingerprinting
	JA4T  string `json:"ja4t,omitempty"`
	JA4TS string `json:"ja4ts,omitempty"`

	// Protocol metadata (populated by dissectors, at most one per session)
	ProtocolMeta any `json:"protocol_meta,omitempty"`
}

// TotalBytes returns the combined byte count for both directions.
func (s *SessionMeta) TotalBytes() uint64 {
	return s.OrigBytes + s.RespBytes
}

// TotalPackets returns the combined packet count for both directions.
func (s *SessionMeta) TotalPackets() uint64 {
	return s.OrigPackets + s.RespPackets
}
