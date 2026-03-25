package common

import (
	"fmt"
	"net"
	"time"
)

const sourceType = "akeso_ndr"

// ---------------------------------------------------------------------------
// SessionMeta → ECSEvent
// ---------------------------------------------------------------------------

// MapSessionToECS converts a SessionMeta into an ECS-normalized event.
// If the session carries protocol metadata, the appropriate ECS protocol
// fields are populated via the protocol-specific mappers below.
func MapSessionToECS(s *SessionMeta) ECSEvent {
	dataset := "ndr:session"
	if s.Service != "" {
		dataset = "ndr:" + s.Service
	}

	e := ECSEvent{
		Timestamp:  s.StartTime,
		SourceType: sourceType,
		Event: ECSEventField{
			Kind:     "event",
			Category: "network",
			Type:     "connection",
			Duration: int64(s.Duration),
			Dataset:  dataset,
		},
		Source: ECSEndpoint{
			IP:      ipString(s.Flow.SrcIP),
			Port:    int(s.Flow.SrcPort),
			MAC:     s.SrcMAC,
			Bytes:   s.OrigBytes,
			Packets: s.OrigPackets,
		},
		Destination: ECSEndpoint{
			IP:      ipString(s.Flow.DstIP),
			Port:    int(s.Flow.DstPort),
			MAC:     s.DstMAC,
			Bytes:   s.RespBytes,
			Packets: s.RespPackets,
		},
		Network: ECSNetwork{
			Transport:   string(s.Transport),
			Protocol:    s.Service,
			Direction:   string(s.Direction),
			Bytes:       s.TotalBytes(),
			CommunityID: s.CommunityID,
		},
		NDR: &ECSNDR{
			Session: &ECSNDRSession{ConnState: string(s.ConnState)},
		},
	}

	// Map protocol-specific metadata if present.
	if s.ProtocolMeta != nil {
		mapProtocolMeta(&e, s.ProtocolMeta)
	}

	return e
}

// mapProtocolMeta dispatches to the correct protocol mapper based on type.
func mapProtocolMeta(e *ECSEvent, meta any) {
	switch m := meta.(type) {
	case *DNSMeta:
		mapDNSMeta(e, m)
	case DNSMeta:
		mapDNSMeta(e, &m)
	case *HTTPMeta:
		mapHTTPMeta(e, m)
	case HTTPMeta:
		mapHTTPMeta(e, &m)
	case *TLSMeta:
		mapTLSMeta(e, m)
	case TLSMeta:
		mapTLSMeta(e, &m)
	case *SMBMeta:
		mapSMBMeta(e, m)
	case SMBMeta:
		mapSMBMeta(e, &m)
	case *KerberosMeta:
		mapKerberosMeta(e, m)
	case KerberosMeta:
		mapKerberosMeta(e, &m)
	case *SSHMeta:
		mapSSHMeta(e, m)
	case SSHMeta:
		mapSSHMeta(e, &m)
	}
}

func mapDNSMeta(e *ECSEvent, m *DNSMeta) {
	flags := dnsFlags(m)
	answers := make([]ECSDNSAnswer, len(m.Answers))
	for i, a := range m.Answers {
		answers[i] = ECSDNSAnswer{Data: a.Data, Type: a.Type, TTL: int(a.TTL)}
	}
	e.DNS = &ECSDNS{
		Question:     ECSDNSQuestion{Name: m.Query, Type: m.QTypeName},
		Answers:      answers,
		ResponseCode: m.RCodeName,
		HeaderFlags:  flags,
	}
}

func dnsFlags(m *DNSMeta) []string {
	var flags []string
	if m.AA {
		flags = append(flags, "AA")
	}
	if m.RD {
		flags = append(flags, "RD")
	}
	if m.RA {
		flags = append(flags, "RA")
	}
	if m.TC {
		flags = append(flags, "TC")
	}
	return flags
}

func mapHTTPMeta(e *ECSEvent, m *HTTPMeta) {
	e.Event.Action = m.Method
	e.HTTP = &ECSHTTP{
		Request:  ECSHTTPRequest{Method: m.Method, BodyBytes: m.RequestBodyLen},
		Response: ECSHTTPResponse{StatusCode: m.StatusCode, BodyBytes: m.ResponseBodyLen},
	}
	if m.URI != "" {
		uri := m.URI
		if m.Host != "" {
			uri = fmt.Sprintf("http://%s%s", m.Host, m.URI)
		}
		e.URL = &ECSURL{Full: uri}
	}
	if m.UserAgent != "" {
		e.UserAgent = &ECSUserAgent{Original: m.UserAgent}
	}
}

func mapTLSMeta(e *ECSEvent, m *TLSMeta) {
	e.TLS = &ECSTLS{
		Version: m.Version,
		Cipher:  m.Cipher,
		Client: ECSTLSClient{
			JA3:        m.JA3,
			JA4:        m.JA4,
			ServerName: m.ServerName,
		},
		Server: ECSTLSServer{
			JA3S:        m.JA3S,
			JA4S:        m.JA4S,
			Certificate: m.Subject,
		},
	}
}

func mapSMBMeta(e *ECSEvent, m *SMBMeta) {
	e.Event.Action = m.Action
	e.SMB = &ECSSMB{
		Version:  m.Version,
		Action:   m.Action,
		Filename: m.Name,
		Path:     m.Path,
		Domain:   m.Domain,
		Username: m.Username,
	}
}

func mapKerberosMeta(e *ECSEvent, m *KerberosMeta) {
	e.Event.Action = m.RequestType
	e.Kerberos = &ECSKerberos{
		RequestType: m.RequestType,
		Client:      m.Client,
		Service:     m.Service,
		Cipher:      m.RepCipher,
		Success:     m.Success,
		ErrorCode:   m.ErrorCode,
	}
}

func mapSSHMeta(e *ECSEvent, m *SSHMeta) {
	e.SSH = &ECSSSH{
		Client:      m.Client,
		Server:      m.Server,
		HASSH:       m.HASSH,
		HASSHServer: m.HASSHServer,
	}
}

// ---------------------------------------------------------------------------
// Detection → ECSEvent
// ---------------------------------------------------------------------------

// MapDetectionToECS converts a Detection into an ECS-normalized alert event.
func MapDetectionToECS(d *Detection) ECSEvent {
	e := ECSEvent{
		Timestamp:  d.Timestamp,
		SourceType: sourceType,
		Event: ECSEventField{
			Kind:     "alert",
			Category: "network",
			Type:     "info",
			Action:   string(d.Type),
			Dataset:  "ndr:detection",
		},
		Source: ECSEndpoint{
			IP:   d.SrcIP,
			Port: int(d.SrcPort),
		},
		Destination: ECSEndpoint{
			IP:   d.DstIP,
			Port: int(d.DstPort),
		},
		Network: ECSNetwork{
			CommunityID: d.CommunityID,
		},
		Threat: &ECSThreat{
			Technique: ECSThreatTechnique{
				ID:   d.MITRE.TechniqueID,
				Name: d.MITRE.TechniqueName,
			},
			Tactic: ECSThreatTactic{
				ID:   d.MITRE.TacticID,
				Name: d.MITRE.TacticName,
			},
		},
		NDR: &ECSNDR{
			Detection: &ECSNDRDetection{
				Name:     d.Name,
				Severity: int(d.Severity),
			},
		},
	}

	// Propagate beacon-specific evidence into ndr.beacon if present.
	if mean, ok := d.Evidence["interval_mean"].(float64); ok {
		if e.NDR.Beacon == nil {
			e.NDR.Beacon = &ECSNDRBeacon{}
		}
		e.NDR.Beacon.IntervalMean = mean
	}
	if stddev, ok := d.Evidence["interval_stddev"].(float64); ok {
		if e.NDR.Beacon == nil {
			e.NDR.Beacon = &ECSNDRBeacon{}
		}
		e.NDR.Beacon.IntervalStddev = stddev
	}

	return e
}

// ---------------------------------------------------------------------------
// HostScore → ECSEvent
// ---------------------------------------------------------------------------

// MapHostScoreToECS converts a HostScore into an ECS-normalized metric event.
func MapHostScoreToECS(h *HostScore) ECSEvent {
	return ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: sourceType,
		Event: ECSEventField{
			Kind:     "metric",
			Category: "network",
			Type:     "info",
			Dataset:  "ndr:host_score",
		},
		Source: ECSEndpoint{
			IP:     h.IP,
			Domain: h.Hostname,
		},
		Network: ECSNetwork{},
		NDR: &ECSNDR{
			HostScore: &ECSNDRHostScore{
				Threat:    h.ThreatScore,
				Certainty: h.CertaintyScore,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
