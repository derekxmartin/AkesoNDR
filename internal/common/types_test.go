package common

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// helper to round-trip a value through JSON marshal/unmarshal.
func roundTrip[T any](t *testing.T, label string, orig T) T {
	t.Helper()
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("%s: marshal error: %v", label, err)
	}
	var decoded T
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("%s: unmarshal error: %v", label, err)
	}
	return decoded
}

// ---------------------------------------------------------------------------
// SessionMeta
// ---------------------------------------------------------------------------

func TestSessionMetaRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond).UTC()
	orig := SessionMeta{
		ID:          "sess-001",
		CommunityID: "1:abc123",
		Flow: FlowKey{
			SrcIP:    net.ParseIP("10.0.0.100"),
			DstIP:    net.ParseIP("93.184.216.34"),
			SrcPort:  54321,
			DstPort:  80,
			Protocol: 6,
		},
		Transport:   TransportTCP,
		Service:     "http",
		Direction:   DirectionOutbound,
		StartTime:   now,
		EndTime:     now.Add(5 * time.Second),
		Duration:    5 * time.Second,
		ConnState:   ConnStateSF,
		OrigBytes:   1024,
		OrigPackets: 10,
		RespBytes:   4096,
		RespPackets: 8,
		VLANID:      100,
		SrcMAC:      "aa:bb:cc:dd:ee:ff",
		DstMAC:      "11:22:33:44:55:66",
	}

	decoded := roundTrip(t, "SessionMeta", orig)

	if decoded.ID != orig.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, orig.ID)
	}
	if decoded.CommunityID != orig.CommunityID {
		t.Errorf("CommunityID: got %q, want %q", decoded.CommunityID, orig.CommunityID)
	}
	if decoded.Flow.SrcPort != orig.Flow.SrcPort {
		t.Errorf("SrcPort: got %d, want %d", decoded.Flow.SrcPort, orig.Flow.SrcPort)
	}
	if decoded.ConnState != orig.ConnState {
		t.Errorf("ConnState: got %q, want %q", decoded.ConnState, orig.ConnState)
	}
	if decoded.TotalBytes() != orig.TotalBytes() {
		t.Errorf("TotalBytes: got %d, want %d", decoded.TotalBytes(), orig.TotalBytes())
	}
	if decoded.TotalPackets() != orig.TotalPackets() {
		t.Errorf("TotalPackets: got %d, want %d", decoded.TotalPackets(), orig.TotalPackets())
	}
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

func TestDetectionRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond).UTC()
	orig := Detection{
		ID:        "det-001",
		Name:      "C2 Beacon Detected",
		Type:      DetectionBeacon,
		Timestamp: now,
		Severity:  8,
		Certainty: 7,
		MITRE: MITRETechnique{
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			TacticID:      "TA0011",
			TacticName:    "Command and Control",
		},
		SrcIP:       "10.0.0.100",
		DstIP:       "198.51.100.1",
		SrcPort:     54321,
		DstPort:     443,
		Evidence:    map[string]any{"interval_mean": 60.0, "jitter_ratio": 0.05},
		PcapRef:     "/pcap/det-001.pcap",
		SessionID:   "sess-042",
		CommunityID: "1:xyz789",
		Description: "Regular outbound HTTPS beacon with low jitter",
	}

	decoded := roundTrip(t, "Detection", orig)

	if decoded.ID != orig.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, orig.ID)
	}
	if decoded.Type != orig.Type {
		t.Errorf("Type: got %q, want %q", decoded.Type, orig.Type)
	}
	if decoded.Severity != orig.Severity {
		t.Errorf("Severity: got %d, want %d", decoded.Severity, orig.Severity)
	}
	if decoded.MITRE.TechniqueID != orig.MITRE.TechniqueID {
		t.Errorf("MITRE TechniqueID: got %q, want %q", decoded.MITRE.TechniqueID, orig.MITRE.TechniqueID)
	}
	if decoded.Evidence["interval_mean"] != orig.Evidence["interval_mean"] {
		t.Errorf("Evidence interval_mean: got %v, want %v", decoded.Evidence["interval_mean"], orig.Evidence["interval_mean"])
	}
}

// ---------------------------------------------------------------------------
// HostScore
// ---------------------------------------------------------------------------

func TestHostScoreRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond).UTC()
	orig := HostScore{
		IP:             "10.0.0.100",
		Hostname:       "workstation-1",
		ThreatScore:    72,
		CertaintyScore: 85,
		Quadrant:       QuadrantCritical,
		ActiveDetections:     3,
		DetectionTypes:       []string{"c2_beacon", "lateral_movement", "data_exfiltration"},
		MITRETacticsObserved: []string{"Command and Control", "Lateral Movement", "Exfiltration"},
		ScoreHistory: []ScoreSnapshot{
			{Timestamp: now.Add(-1 * time.Hour), ThreatScore: 45, CertaintyScore: 60},
			{Timestamp: now, ThreatScore: 72, CertaintyScore: 85},
		},
		FirstSeen:   now.Add(-24 * time.Hour),
		LastUpdated: now,
	}

	decoded := roundTrip(t, "HostScore", orig)

	if decoded.IP != orig.IP {
		t.Errorf("IP: got %q, want %q", decoded.IP, orig.IP)
	}
	if decoded.ThreatScore != orig.ThreatScore {
		t.Errorf("ThreatScore: got %d, want %d", decoded.ThreatScore, orig.ThreatScore)
	}
	if decoded.Quadrant != orig.Quadrant {
		t.Errorf("Quadrant: got %q, want %q", decoded.Quadrant, orig.Quadrant)
	}
	if len(decoded.ScoreHistory) != len(orig.ScoreHistory) {
		t.Errorf("ScoreHistory len: got %d, want %d", len(decoded.ScoreHistory), len(orig.ScoreHistory))
	}
	if len(decoded.DetectionTypes) != len(orig.DetectionTypes) {
		t.Errorf("DetectionTypes len: got %d, want %d", len(decoded.DetectionTypes), len(orig.DetectionTypes))
	}
}

func TestComputeQuadrant(t *testing.T) {
	tests := []struct {
		threat, certainty int
		want              Quadrant
	}{
		{0, 0, QuadrantLow},
		{20, 20, QuadrantLow},
		{30, 30, QuadrantMedium},
		{50, 50, QuadrantHigh},
		{80, 90, QuadrantCritical},
		{100, 100, QuadrantCritical},
	}
	for _, tt := range tests {
		got := ComputeQuadrant(tt.threat, tt.certainty)
		if got != tt.want {
			t.Errorf("ComputeQuadrant(%d, %d) = %q, want %q", tt.threat, tt.certainty, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Protocol Meta — round-trip one of each
// ---------------------------------------------------------------------------

func TestDNSMetaRoundTrip(t *testing.T) {
	orig := DNSMeta{
		Query:         "evil.example.com",
		QType:         1,
		QTypeName:     "A",
		QClass:        1,
		QClassName:    "IN",
		Answers:       []DNSAnswer{{Data: "93.184.216.34", Type: "A", TTL: 3600}},
		RCode:         0,
		RCodeName:     "NOERROR",
		AA:            true,
		RD:            true,
		RA:            true,
		TransID:       0xABCD,
		Proto:         "udp",
		TTLs:          []uint32{3600},
		TotalAnswers:  1,
		Entropy:       3.45,
		SubdomainDepth: 2,
		QueryLength:   17,
	}

	decoded := roundTrip(t, "DNSMeta", orig)
	if decoded.Query != orig.Query {
		t.Errorf("Query: got %q, want %q", decoded.Query, orig.Query)
	}
	if decoded.Entropy != orig.Entropy {
		t.Errorf("Entropy: got %f, want %f", decoded.Entropy, orig.Entropy)
	}
}

func TestHTTPMetaRoundTrip(t *testing.T) {
	orig := HTTPMeta{
		Method:          "POST",
		URI:             "/api/exfil",
		Host:            "evil.example.com",
		UserAgent:       "Mozilla/5.0",
		StatusCode:      200,
		StatusMsg:       "OK",
		RequestBodyLen:  2048,
		ResponseBodyLen: 128,
	}
	decoded := roundTrip(t, "HTTPMeta", orig)
	if decoded.Method != orig.Method {
		t.Errorf("Method: got %q, want %q", decoded.Method, orig.Method)
	}
	if decoded.RequestBodyLen != orig.RequestBodyLen {
		t.Errorf("RequestBodyLen: got %d, want %d", decoded.RequestBodyLen, orig.RequestBodyLen)
	}
}

func TestTLSMetaRoundTrip(t *testing.T) {
	orig := TLSMeta{
		Version:    "TLS 1.3",
		Cipher:     "TLS_AES_256_GCM_SHA384",
		ServerName: "example.com",
		JA3:        "abc123",
		Established: true,
		SANDNSNames: []string{"example.com", "www.example.com"},
	}
	decoded := roundTrip(t, "TLSMeta", orig)
	if decoded.ServerName != orig.ServerName {
		t.Errorf("ServerName: got %q, want %q", decoded.ServerName, orig.ServerName)
	}
	if len(decoded.SANDNSNames) != len(orig.SANDNSNames) {
		t.Errorf("SANDNSNames len: got %d, want %d", len(decoded.SANDNSNames), len(orig.SANDNSNames))
	}
}

func TestSMBMetaRoundTrip(t *testing.T) {
	orig := SMBMeta{Version: "SMBv2", Action: "write", Path: `\\ADMIN$`, Username: "admin"}
	decoded := roundTrip(t, "SMBMeta", orig)
	if decoded.Action != orig.Action {
		t.Errorf("Action: got %q, want %q", decoded.Action, orig.Action)
	}
}

func TestKerberosMetaRoundTrip(t *testing.T) {
	orig := KerberosMeta{
		RequestType: "TGS", Client: "user@DOMAIN.COM", Service: "krbtgt/DOMAIN.COM",
		Success: true, ReqCiphers: []int{17, 18, 23}, RepCipher: 18,
	}
	decoded := roundTrip(t, "KerberosMeta", orig)
	if decoded.Client != orig.Client {
		t.Errorf("Client: got %q, want %q", decoded.Client, orig.Client)
	}
}

func TestSSHMetaRoundTrip(t *testing.T) {
	orig := SSHMeta{Client: "OpenSSH_8.9", Server: "OpenSSH_9.0", Version: 2, CipherAlg: "aes256-ctr"}
	decoded := roundTrip(t, "SSHMeta", orig)
	if decoded.Version != orig.Version {
		t.Errorf("Version: got %d, want %d", decoded.Version, orig.Version)
	}
}

func TestSMTPMetaRoundTrip(t *testing.T) {
	orig := SMTPMeta{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", TLS: true}
	decoded := roundTrip(t, "SMTPMeta", orig)
	if decoded.From != orig.From {
		t.Errorf("From: got %q, want %q", decoded.From, orig.From)
	}
}

func TestRDPMetaRoundTrip(t *testing.T) {
	orig := RDPMeta{ClientName: "WORKSTATION", DesktopWidth: 1920, DesktopHeight: 1080}
	decoded := roundTrip(t, "RDPMeta", orig)
	if decoded.DesktopWidth != orig.DesktopWidth {
		t.Errorf("DesktopWidth: got %d, want %d", decoded.DesktopWidth, orig.DesktopWidth)
	}
}

func TestNTLMMetaRoundTrip(t *testing.T) {
	orig := NTLMMeta{Domain: "CORP", Hostname: "DC01", Username: "admin", Success: true}
	decoded := roundTrip(t, "NTLMMeta", orig)
	if decoded.Domain != orig.Domain {
		t.Errorf("Domain: got %q, want %q", decoded.Domain, orig.Domain)
	}
}

func TestLDAPMetaRoundTrip(t *testing.T) {
	orig := LDAPMeta{BaseObject: "dc=corp,dc=com", Query: "(objectClass=*)", ResultCode: 0}
	decoded := roundTrip(t, "LDAPMeta", orig)
	if decoded.BaseObject != orig.BaseObject {
		t.Errorf("BaseObject: got %q, want %q", decoded.BaseObject, orig.BaseObject)
	}
}

func TestDCERPCMetaRoundTrip(t *testing.T) {
	orig := DCERPCMeta{Endpoint: "svcctl", Operation: "CreateServiceW", Username: "admin"}
	decoded := roundTrip(t, "DCERPCMeta", orig)
	if decoded.Endpoint != orig.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", decoded.Endpoint, orig.Endpoint)
	}
}
