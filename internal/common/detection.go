package common

import "time"

// DetectionType categorizes the behavioral detection.
type DetectionType string

const (
	DetectionBeacon           DetectionType = "c2_beacon"
	DetectionDNSTunnel        DetectionType = "dns_tunnel"
	DetectionLateralMovement  DetectionType = "lateral_movement"
	DetectionExfiltration     DetectionType = "data_exfiltration"
	DetectionKerberoasting    DetectionType = "kerberoasting"
	DetectionASREPRoast       DetectionType = "asrep_roast"
	DetectionGoldenTicket     DetectionType = "golden_ticket"
	DetectionNTLMRelay        DetectionType = "ntlm_relay"
	DetectionLDAPCleartext    DetectionType = "ldap_cleartext_bind"
	DetectionPassTheHash      DetectionType = "pass_the_hash"
	DetectionRemoteExec       DetectionType = "remote_execution"
	DetectionHiddenTunnel     DetectionType = "hidden_tunnel"
	DetectionPortScan         DetectionType = "port_scan"
	DetectionServiceEnum      DetectionType = "service_enumeration"
	DetectionSignatureMatch   DetectionType = "signature_match"
)

// Detection represents a single behavioral or signature-based alert.
// Produced by the detection engine (akeso-detect) or signature engine (akeso-signatures).
type Detection struct {
	// Identity
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Type      DetectionType `json:"type"`
	Timestamp time.Time     `json:"timestamp"`

	// Scoring
	Severity  Severity `json:"severity"`  // 1-10
	Certainty Severity `json:"certainty"` // 1-10

	// MITRE ATT&CK mapping
	MITRE MITRETechnique `json:"mitre"`

	// Network context
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	// Evidence — arbitrary key/value pairs specific to the detection type.
	// Examples: beacon interval stats, DNS entropy values, file paths, etc.
	Evidence map[string]any `json:"evidence,omitempty"`

	// PCAP reference for analyst investigation
	PcapRef string `json:"pcap_ref,omitempty"`

	// Session reference
	SessionID   string `json:"session_id,omitempty"`
	CommunityID string `json:"community_id,omitempty"`

	// Description is a human-readable summary of the detection.
	Description string `json:"description,omitempty"`
}
