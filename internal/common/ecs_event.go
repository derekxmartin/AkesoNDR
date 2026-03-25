package common

import "time"

// ECSEvent is the top-level Elastic Common Schema event envelope.
// All AkesoNDR telemetry — sessions, protocol metadata, detections, host
// scores — is normalized into this structure before export to AkesoSIEM.
type ECSEvent struct {
	// --- event.* ---
	Event ECSEventField `json:"event"`

	// --- source.* / destination.* ---
	Source      ECSEndpoint `json:"source"`
	Destination ECSEndpoint `json:"destination"`

	// --- network.* ---
	Network ECSNetwork `json:"network"`

	// --- Protocol-specific (at most one populated per event) ---
	DNS      *ECSDNS      `json:"dns,omitempty"`
	HTTP     *ECSHTTP     `json:"http,omitempty"`
	URL      *ECSURL      `json:"url,omitempty"`
	UserAgent *ECSUserAgent `json:"user_agent,omitempty"`
	TLS      *ECSTLS      `json:"tls,omitempty"`
	SSH      *ECSSSH      `json:"ssh,omitempty"`

	// --- Custom extensions (non-standard ECS) ---
	SMB      *ECSSMB      `json:"smb,omitempty"`
	Kerberos *ECSKerberos `json:"kerberos,omitempty"`
	NDR      *ECSNDR      `json:"ndr,omitempty"`

	// --- threat.* (MITRE ATT&CK) ---
	Threat *ECSThreat `json:"threat,omitempty"`

	// --- Metadata ---
	Timestamp  time.Time         `json:"@timestamp"`
	SourceType string            `json:"source_type"` // always "akeso_ndr"
	Labels     map[string]string `json:"labels,omitempty"`
}

// ---------------------------------------------------------------------------
// event.*
// ---------------------------------------------------------------------------

// ECSEventField covers the event.* field group.
type ECSEventField struct {
	Kind     string `json:"kind"`               // "event", "alert", "metric"
	Category string `json:"category"`           // "network"
	Type     string `json:"type"`               // "connection", "protocol", "info"
	Action   string `json:"action,omitempty"`    // protocol-specific action
	Duration int64  `json:"duration,omitempty"` // nanoseconds
	Dataset  string `json:"dataset"`            // "ndr:session", "ndr:dns", "ndr:detection", etc.
}

// ---------------------------------------------------------------------------
// source.* / destination.*
// ---------------------------------------------------------------------------

// ECSEndpoint represents either source or destination in ECS.
type ECSEndpoint struct {
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	Domain  string `json:"domain,omitempty"`
	MAC     string `json:"mac,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`
	Packets uint64 `json:"packets,omitempty"`
}

// ---------------------------------------------------------------------------
// network.*
// ---------------------------------------------------------------------------

// ECSNetwork covers the network.* field group.
type ECSNetwork struct {
	Transport   string `json:"transport"`              // tcp, udp, icmp
	Protocol    string `json:"protocol,omitempty"`     // http, dns, tls, smb, ...
	Direction   string `json:"direction,omitempty"`    // internal, external, inbound, outbound
	Bytes       uint64 `json:"bytes,omitempty"`
	CommunityID string `json:"community_id,omitempty"`
}

// ---------------------------------------------------------------------------
// dns.*
// ---------------------------------------------------------------------------

// ECSDNSQuestion represents dns.question.
type ECSDNSQuestion struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ECSDNSAnswer represents a single dns.answers entry.
type ECSDNSAnswer struct {
	Data string `json:"data"`
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
}

// ECSDNS covers the dns.* field group.
type ECSDNS struct {
	Question     ECSDNSQuestion `json:"question"`
	Answers      []ECSDNSAnswer `json:"answers,omitempty"`
	ResponseCode string         `json:"response_code"`
	HeaderFlags  []string       `json:"header_flags,omitempty"`
}

// ---------------------------------------------------------------------------
// http.* / url.* / user_agent.*
// ---------------------------------------------------------------------------

// ECSHTTPRequest represents http.request.
type ECSHTTPRequest struct {
	Method    string `json:"method"`
	BodyBytes int64  `json:"body.bytes,omitempty"`
}

// ECSHTTPResponse represents http.response.
type ECSHTTPResponse struct {
	StatusCode int   `json:"status_code"`
	BodyBytes  int64 `json:"body.bytes,omitempty"`
}

// ECSHTTP covers the http.* field group.
type ECSHTTP struct {
	Request  ECSHTTPRequest  `json:"request"`
	Response ECSHTTPResponse `json:"response"`
}

// ECSURL covers the url.* field group.
type ECSURL struct {
	Full string `json:"full"`
}

// ECSUserAgent covers the user_agent.* field group.
type ECSUserAgent struct {
	Original string `json:"original"`
}

// ---------------------------------------------------------------------------
// tls.*
// ---------------------------------------------------------------------------

// ECSTLSClient represents tls.client.
type ECSTLSClient struct {
	JA3        string `json:"ja3,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	ServerName string `json:"server_name,omitempty"` // SNI
}

// ECSTLSServer represents tls.server.
type ECSTLSServer struct {
	JA3S        string `json:"ja3s,omitempty"`
	JA4S        string `json:"ja4s,omitempty"`
	Certificate string `json:"certificate,omitempty"` // subject DN
}

// ECSTLS covers the tls.* field group.
type ECSTLS struct {
	Version string       `json:"version"`
	Cipher  string       `json:"cipher"`
	Client  ECSTLSClient `json:"client"`
	Server  ECSTLSServer `json:"server"`
}

// ---------------------------------------------------------------------------
// ssh.*
// ---------------------------------------------------------------------------

// ECSSSH covers the ssh.* field group.
type ECSSSH struct {
	Client      string `json:"client"`
	Server      string `json:"server"`
	HASSH       string `json:"hassh,omitempty"`
	HASSHServer string `json:"hassh_server,omitempty"`
}

// ---------------------------------------------------------------------------
// Custom extensions: smb.*, kerberos.*
// ---------------------------------------------------------------------------

// ECSSMB covers the smb.* custom extension.
type ECSSMB struct {
	Version  string `json:"version"`
	Action   string `json:"action"`
	Filename string `json:"filename,omitempty"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Username string `json:"username,omitempty"`
}

// ECSKerberos covers the kerberos.* custom extension.
type ECSKerberos struct {
	RequestType string `json:"request_type"`
	Client      string `json:"client"`
	Service     string `json:"service"`
	Cipher      int    `json:"cipher,omitempty"`
	Success     bool   `json:"success"`
	ErrorCode   int    `json:"error_code,omitempty"`
}

// ---------------------------------------------------------------------------
// threat.* (MITRE ATT&CK)
// ---------------------------------------------------------------------------

// ECSThreatTechnique represents threat.technique.
type ECSThreatTechnique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ECSThreatTactic represents threat.tactic.
type ECSThreatTactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ECSThreat covers the threat.* field group.
type ECSThreat struct {
	Technique ECSThreatTechnique `json:"technique"`
	Tactic    ECSThreatTactic    `json:"tactic"`
}

// ---------------------------------------------------------------------------
// ndr.* (AkesoNDR custom extension)
// ---------------------------------------------------------------------------

// ECSNDRDetection covers ndr.detection.* fields.
type ECSNDRDetection struct {
	Name     string `json:"name,omitempty"`
	Severity int    `json:"severity,omitempty"`
}

// ECSNDRHostScore covers ndr.host_score.* fields.
type ECSNDRHostScore struct {
	Threat    int `json:"threat,omitempty"`
	Certainty int `json:"certainty,omitempty"`
}

// ECSNDRBeacon covers ndr.beacon.* fields.
type ECSNDRBeacon struct {
	IntervalMean   float64 `json:"interval_mean,omitempty"`
	IntervalStddev float64 `json:"interval_stddev,omitempty"`
}

// ECSNDRSession covers ndr.session.* fields.
type ECSNDRSession struct {
	ConnState string `json:"conn_state,omitempty"`
}

// ECSNDR covers the ndr.* custom extension field group.
type ECSNDR struct {
	Detection *ECSNDRDetection `json:"detection,omitempty"`
	HostScore *ECSNDRHostScore `json:"host_score,omitempty"`
	Beacon    *ECSNDRBeacon    `json:"beacon,omitempty"`
	Session   *ECSNDRSession   `json:"session,omitempty"`
}
