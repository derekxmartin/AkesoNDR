package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
)

func testServer() (*Server, *DataStore) {
	store := NewDataStore()
	store.Health = SensorHealth{
		Status:          "running",
		StartTime:       time.Now().Add(-1 * time.Hour),
		PacketsCaptured: 100000,
		PacketsDropped:  5,
		BytesCaptured:   50000000,
		PPS:             1500,
		BPS:             750000,
		ActiveSessions:  42,
		DetectionEngine: "active",
	}
	store.Hosts = []common.HostScore{
		{IP: "10.0.0.1", Hostname: "workstation-1", ThreatScore: 80, CertaintyScore: 75, Quadrant: common.QuadrantCritical},
		{IP: "10.0.0.2", Hostname: "workstation-2", ThreatScore: 30, CertaintyScore: 20, Quadrant: common.QuadrantMedium},
	}
	store.Detections = []common.Detection{
		{
			ID: "det-001", Name: "C2 Beacon", Type: common.DetectionBeacon,
			Severity: 8, Certainty: 7, SrcIP: "10.0.0.1", DstIP: "198.51.100.1",
			Timestamp: time.Now(),
			MITRE: common.MITRETechnique{
				TechniqueID: "T1071", TechniqueName: "Application Layer Protocol",
				TacticID: "TA0011", TacticName: "Command and Control",
			},
		},
		{
			ID: "det-002", Name: "Port Scan", Type: common.DetectionPortScan,
			Severity: 4, Certainty: 9, SrcIP: "10.0.0.3", DstIP: "10.0.0.0/24",
			Timestamp: time.Now(),
			MITRE: common.MITRETechnique{
				TechniqueID: "T1046", TechniqueName: "Network Service Discovery",
				TacticID: "TA0007", TacticName: "Discovery",
			},
		},
	}
	store.ProtocolStats = ProtocolStats{
		DNS:  ProtocolCount{Sessions: 5000, Bytes: 250000},
		HTTP: ProtocolCount{Sessions: 3000, Bytes: 15000000},
		TLS:  ProtocolCount{Sessions: 8000, Bytes: 45000000},
	}

	srv := NewServer(":0", store, "")
	return srv, store
}

func doGet(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestAPI_Health(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/health")

	if rr.Code != 200 {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var health SensorHealth
	json.Unmarshal(rr.Body.Bytes(), &health)

	if health.Status != "running" {
		t.Errorf("Status = %q, want running", health.Status)
	}
	if health.PacketsCaptured != 100000 {
		t.Errorf("PacketsCaptured = %d, want 100000", health.PacketsCaptured)
	}
	if health.Uptime == "" {
		t.Error("Uptime should be populated")
	}
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

func TestAPI_Hosts(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/hosts")

	if rr.Code != 200 {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	total := int(resp["total"].(float64))
	if total != 2 {
		t.Errorf("Total hosts = %d, want 2", total)
	}
}

func TestAPI_HostDetail(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/hosts/10.0.0.1")

	if rr.Code != 200 {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	host := resp["host"].(map[string]any)
	if host["ip"] != "10.0.0.1" {
		t.Errorf("Host IP = %v, want 10.0.0.1", host["ip"])
	}

	dets := resp["detections"].([]any)
	if len(dets) != 1 {
		t.Errorf("Detections for 10.0.0.1 = %d, want 1", len(dets))
	}
}

func TestAPI_HostDetail_NotFound(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/hosts/99.99.99.99")

	if rr.Code != 404 {
		t.Errorf("Status = %d, want 404", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

func TestAPI_Detections(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/detections")

	if rr.Code != 200 {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	total := int(resp["total"].(float64))
	if total != 2 {
		t.Errorf("Total detections = %d, want 2", total)
	}
}

func TestAPI_Detections_FilterByType(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/detections?type=c2_beacon")

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	total := int(resp["total"].(float64))
	if total != 1 {
		t.Errorf("Filtered detections = %d, want 1", total)
	}
}

func TestAPI_Detections_FilterByHost(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/detections?host=10.0.0.3")

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	total := int(resp["total"].(float64))
	if total != 1 {
		t.Errorf("Filtered by host = %d, want 1", total)
	}
}

func TestAPI_DetectionDetail(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/detections/det-001")

	if rr.Code != 200 {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var det common.Detection
	json.Unmarshal(rr.Body.Bytes(), &det)
	if det.Name != "C2 Beacon" {
		t.Errorf("Name = %q, want C2 Beacon", det.Name)
	}
}

func TestAPI_DetectionDetail_NotFound(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/detections/nonexistent")

	if rr.Code != 404 {
		t.Errorf("Status = %d, want 404", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Protocols
// ---------------------------------------------------------------------------

func TestAPI_Protocols(t *testing.T) {
	srv, _ := testServer()
	rr := doGet(t, srv.Router(), "/api/v1/protocols")

	if rr.Code != 200 {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var stats ProtocolStats
	json.Unmarshal(rr.Body.Bytes(), &stats)

	if stats.DNS.Sessions != 5000 {
		t.Errorf("DNS sessions = %d, want 5000", stats.DNS.Sessions)
	}
	if stats.TLS.Bytes != 45000000 {
		t.Errorf("TLS bytes = %d, want 45000000", stats.TLS.Bytes)
	}
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

func TestAPI_Signatures(t *testing.T) {
	srv, store := testServer()
	store.SignatureCount = 150
	store.SignatureErrors = 3

	rr := doGet(t, srv.Router(), "/api/v1/signatures")

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if int(resp["loaded"].(float64)) != 150 {
		t.Errorf("Loaded = %v, want 150", resp["loaded"])
	}
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

func TestAPI_CORS(t *testing.T) {
	srv, _ := testServer()
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("CORS headers should be present")
	}
}
