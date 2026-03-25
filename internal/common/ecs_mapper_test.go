package common

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// SessionMeta → ECS round-trip
// ---------------------------------------------------------------------------

func TestMapSessionToECS_Basic(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond).UTC()
	s := &SessionMeta{
		ID:          "sess-001",
		CommunityID: "1:abc123",
		Flow: FlowKey{
			SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("93.184.216.34"),
			SrcPort: 54321, DstPort: 80, Protocol: 6,
		},
		Transport: TransportTCP, Service: "http", Direction: DirectionOutbound,
		StartTime: now, Duration: 5 * time.Second, ConnState: ConnStateSF,
		OrigBytes: 1024, OrigPackets: 10, RespBytes: 4096, RespPackets: 8,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}

	e := MapSessionToECS(s)

	// Event fields
	assertEq(t, "event.kind", e.Event.Kind, "event")
	assertEq(t, "event.category", e.Event.Category, "network")
	assertEq(t, "event.dataset", e.Event.Dataset, "ndr:http")

	// Source/Destination
	assertEq(t, "source.ip", e.Source.IP, "10.0.0.100")
	assertEq(t, "destination.ip", e.Destination.IP, "93.184.216.34")
	assertIntEq(t, "source.port", e.Source.Port, 54321)
	assertIntEq(t, "destination.port", e.Destination.Port, 80)
	assertUint64Eq(t, "source.bytes", e.Source.Bytes, 1024)
	assertUint64Eq(t, "destination.packets", e.Destination.Packets, 8)

	// Network
	assertEq(t, "network.transport", e.Network.Transport, "tcp")
	assertEq(t, "network.protocol", e.Network.Protocol, "http")
	assertEq(t, "network.direction", e.Network.Direction, "outbound")
	assertUint64Eq(t, "network.bytes", e.Network.Bytes, 5120)
	assertEq(t, "network.community_id", e.Network.CommunityID, "1:abc123")

	// NDR extension
	if e.NDR == nil || e.NDR.Session == nil {
		t.Fatal("ndr.session is nil")
	}
	assertEq(t, "ndr.session.conn_state", e.NDR.Session.ConnState, "SF")

	// source_type
	assertEq(t, "source_type", e.SourceType, "akeso_ndr")

	// JSON round-trip
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ECSEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assertEq(t, "rt source.ip", decoded.Source.IP, "10.0.0.100")
	assertEq(t, "rt network.community_id", decoded.Network.CommunityID, "1:abc123")
}

// ---------------------------------------------------------------------------
// SessionMeta with DNS protocol meta → ECS
// ---------------------------------------------------------------------------

func TestMapSessionToECS_DNS(t *testing.T) {
	s := &SessionMeta{
		Flow:      FlowKey{SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("8.8.8.8"), SrcPort: 12345, DstPort: 53, Protocol: 17},
		Transport: TransportUDP, Service: "dns", Direction: DirectionOutbound,
		StartTime: time.Now().UTC(), ConnState: ConnStateSF,
		ProtocolMeta: &DNSMeta{
			Query: "example.com", QTypeName: "A", RCodeName: "NOERROR",
			AA: false, RD: true, RA: true,
			Answers: []DNSAnswer{{Data: "93.184.216.34", Type: "A", TTL: 3600}},
		},
	}

	e := MapSessionToECS(s)

	if e.DNS == nil {
		t.Fatal("dns field is nil")
	}
	assertEq(t, "dns.question.name", e.DNS.Question.Name, "example.com")
	assertEq(t, "dns.question.type", e.DNS.Question.Type, "A")
	assertEq(t, "dns.response_code", e.DNS.ResponseCode, "NOERROR")
	if len(e.DNS.Answers) != 1 {
		t.Fatalf("dns.answers len: got %d, want 1", len(e.DNS.Answers))
	}
	assertEq(t, "dns.answers[0].data", e.DNS.Answers[0].Data, "93.184.216.34")
	// Header flags
	if len(e.DNS.HeaderFlags) != 2 {
		t.Fatalf("dns.header_flags len: got %d, want 2 (RD, RA)", len(e.DNS.HeaderFlags))
	}
}

// ---------------------------------------------------------------------------
// SessionMeta with HTTP protocol meta → ECS
// ---------------------------------------------------------------------------

func TestMapSessionToECS_HTTP(t *testing.T) {
	s := &SessionMeta{
		Flow:      FlowKey{SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("93.184.216.34"), SrcPort: 54321, DstPort: 80, Protocol: 6},
		Transport: TransportTCP, Service: "http", Direction: DirectionOutbound,
		StartTime: time.Now().UTC(), ConnState: ConnStateSF,
		ProtocolMeta: &HTTPMeta{
			Method: "POST", URI: "/api/data", Host: "example.com",
			UserAgent: "Mozilla/5.0", StatusCode: 200,
			RequestBodyLen: 2048, ResponseBodyLen: 512,
		},
	}

	e := MapSessionToECS(s)

	if e.HTTP == nil {
		t.Fatal("http field is nil")
	}
	assertEq(t, "http.request.method", e.HTTP.Request.Method, "POST")
	assertIntEq(t, "http.response.status_code", e.HTTP.Response.StatusCode, 200)
	if e.URL == nil {
		t.Fatal("url field is nil")
	}
	assertEq(t, "url.full", e.URL.Full, "http://example.com/api/data")
	if e.UserAgent == nil {
		t.Fatal("user_agent field is nil")
	}
	assertEq(t, "user_agent.original", e.UserAgent.Original, "Mozilla/5.0")
}

// ---------------------------------------------------------------------------
// SessionMeta with TLS protocol meta → ECS
// ---------------------------------------------------------------------------

func TestMapSessionToECS_TLS(t *testing.T) {
	s := &SessionMeta{
		Flow:      FlowKey{SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("1.2.3.4"), SrcPort: 54321, DstPort: 443, Protocol: 6},
		Transport: TransportTCP, Service: "tls", Direction: DirectionOutbound,
		StartTime: time.Now().UTC(), ConnState: ConnStateSF,
		ProtocolMeta: &TLSMeta{
			Version: "TLS 1.3", Cipher: "TLS_AES_256_GCM_SHA384",
			ServerName: "example.com", JA3: "abc", JA3S: "def",
			Subject: "CN=example.com",
		},
	}

	e := MapSessionToECS(s)

	if e.TLS == nil {
		t.Fatal("tls field is nil")
	}
	assertEq(t, "tls.version", e.TLS.Version, "TLS 1.3")
	assertEq(t, "tls.client.server_name", e.TLS.Client.ServerName, "example.com")
	assertEq(t, "tls.client.ja3", e.TLS.Client.JA3, "abc")
	assertEq(t, "tls.server.ja3s", e.TLS.Server.JA3S, "def")
	assertEq(t, "tls.server.certificate", e.TLS.Server.Certificate, "CN=example.com")
}

// ---------------------------------------------------------------------------
// SessionMeta with SMB and Kerberos → ECS
// ---------------------------------------------------------------------------

func TestMapSessionToECS_SMB(t *testing.T) {
	s := &SessionMeta{
		Flow:      FlowKey{SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("10.0.0.5"), SrcPort: 49152, DstPort: 445, Protocol: 6},
		Transport: TransportTCP, Service: "smb", StartTime: time.Now().UTC(), ConnState: ConnStateSF,
		ProtocolMeta: &SMBMeta{Version: "SMBv2", Action: "write", Name: "payload.exe", Path: `\\ADMIN$`, Username: "admin"},
	}
	e := MapSessionToECS(s)
	if e.SMB == nil {
		t.Fatal("smb field is nil")
	}
	assertEq(t, "smb.action", e.SMB.Action, "write")
	assertEq(t, "smb.username", e.SMB.Username, "admin")
	assertEq(t, "event.action", e.Event.Action, "write")
}

func TestMapSessionToECS_Kerberos(t *testing.T) {
	s := &SessionMeta{
		Flow:      FlowKey{SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("10.0.0.1"), SrcPort: 49200, DstPort: 88, Protocol: 6},
		Transport: TransportTCP, Service: "kerberos", StartTime: time.Now().UTC(), ConnState: ConnStateSF,
		ProtocolMeta: &KerberosMeta{RequestType: "TGS", Client: "user@CORP.COM", Service: "krbtgt/CORP.COM", Success: true, RepCipher: 18},
	}
	e := MapSessionToECS(s)
	if e.Kerberos == nil {
		t.Fatal("kerberos field is nil")
	}
	assertEq(t, "kerberos.client", e.Kerberos.Client, "user@CORP.COM")
	assertEq(t, "event.action", e.Event.Action, "TGS")
}

func TestMapSessionToECS_SSH(t *testing.T) {
	s := &SessionMeta{
		Flow:      FlowKey{SrcIP: net.ParseIP("10.0.0.100"), DstIP: net.ParseIP("10.0.0.50"), SrcPort: 49300, DstPort: 22, Protocol: 6},
		Transport: TransportTCP, Service: "ssh", StartTime: time.Now().UTC(), ConnState: ConnStateSF,
		ProtocolMeta: &SSHMeta{Client: "OpenSSH_8.9", Server: "OpenSSH_9.0", HASSH: "abc123"},
	}
	e := MapSessionToECS(s)
	if e.SSH == nil {
		t.Fatal("ssh field is nil")
	}
	assertEq(t, "ssh.client", e.SSH.Client, "OpenSSH_8.9")
	assertEq(t, "ssh.hassh", e.SSH.HASSH, "abc123")
}

// ---------------------------------------------------------------------------
// Detection → ECS
// ---------------------------------------------------------------------------

func TestMapDetectionToECS(t *testing.T) {
	d := &Detection{
		ID: "det-001", Name: "C2 Beacon", Type: DetectionBeacon,
		Timestamp: time.Now().UTC(), Severity: 8, Certainty: 7,
		MITRE: MITRETechnique{TechniqueID: "T1071", TechniqueName: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
		SrcIP: "10.0.0.100", DstIP: "198.51.100.1", SrcPort: 54321, DstPort: 443,
		CommunityID: "1:xyz789",
		Evidence:     map[string]any{"interval_mean": 60.0, "interval_stddev": 3.2},
	}

	e := MapDetectionToECS(d)

	assertEq(t, "event.kind", e.Event.Kind, "alert")
	assertEq(t, "event.dataset", e.Event.Dataset, "ndr:detection")
	assertEq(t, "source.ip", e.Source.IP, "10.0.0.100")
	assertEq(t, "destination.ip", e.Destination.IP, "198.51.100.1")

	// Threat
	if e.Threat == nil {
		t.Fatal("threat is nil")
	}
	assertEq(t, "threat.technique.id", e.Threat.Technique.ID, "T1071")
	assertEq(t, "threat.tactic.name", e.Threat.Tactic.Name, "Command and Control")

	// NDR detection
	if e.NDR == nil || e.NDR.Detection == nil {
		t.Fatal("ndr.detection is nil")
	}
	assertEq(t, "ndr.detection.name", e.NDR.Detection.Name, "C2 Beacon")
	assertIntEq(t, "ndr.detection.severity", e.NDR.Detection.Severity, 8)

	// NDR beacon
	if e.NDR.Beacon == nil {
		t.Fatal("ndr.beacon is nil")
	}
	if e.NDR.Beacon.IntervalMean != 60.0 {
		t.Errorf("ndr.beacon.interval_mean: got %f, want 60.0", e.NDR.Beacon.IntervalMean)
	}
	if e.NDR.Beacon.IntervalStddev != 3.2 {
		t.Errorf("ndr.beacon.interval_stddev: got %f, want 3.2", e.NDR.Beacon.IntervalStddev)
	}

	// JSON round-trip
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ECSEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assertEq(t, "rt threat.technique.id", decoded.Threat.Technique.ID, "T1071")
}

// ---------------------------------------------------------------------------
// HostScore → ECS
// ---------------------------------------------------------------------------

func TestMapHostScoreToECS(t *testing.T) {
	h := &HostScore{
		IP: "10.0.0.100", Hostname: "workstation-1",
		ThreatScore: 72, CertaintyScore: 85,
	}

	e := MapHostScoreToECS(h)

	assertEq(t, "event.kind", e.Event.Kind, "metric")
	assertEq(t, "event.dataset", e.Event.Dataset, "ndr:host_score")
	assertEq(t, "source.ip", e.Source.IP, "10.0.0.100")
	assertEq(t, "source.domain", e.Source.Domain, "workstation-1")

	if e.NDR == nil || e.NDR.HostScore == nil {
		t.Fatal("ndr.host_score is nil")
	}
	assertIntEq(t, "ndr.host_score.threat", e.NDR.HostScore.Threat, 72)
	assertIntEq(t, "ndr.host_score.certainty", e.NDR.HostScore.Certainty, 85)

	// JSON round-trip
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ECSEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assertIntEq(t, "rt ndr.host_score.threat", decoded.NDR.HostScore.Threat, 72)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertEq(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", field, got, want)
	}
}

func assertIntEq(t *testing.T, field string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %d, want %d", field, got, want)
	}
}

func assertUint64Eq(t *testing.T, field string, got, want uint64) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %d, want %d", field, got, want)
	}
}
