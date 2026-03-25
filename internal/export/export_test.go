package export

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// ---------------------------------------------------------------------------
// P8-T1: SIEM Client Tests
// ---------------------------------------------------------------------------

func TestSIEMClient_BatchAndFlush(t *testing.T) {
	var received int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Errorf("Content-Type = %q, want application/x-ndjson", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("X-API-Key = %q, want test-key", r.Header.Get("X-API-Key"))
		}
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		atomic.AddInt64(&received, int64(len(lines)))
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := config.ExportConfig{
		SIEMEndpoint:  server.URL,
		APIKey:        "test-key",
		BatchSize:     5,
		FlushInterval: config.Duration(1 * time.Hour), // won't trigger in test
		MaxRetries:    1,
	}

	client := NewSIEMClient(cfg)

	// Enqueue 5 events (should auto-flush at batch size).
	for i := 0; i < 5; i++ {
		client.Enqueue(common.ECSEvent{
			SourceType: "akeso_ndr",
			Event:      common.ECSEventField{Kind: "event", Category: "network"},
		})
	}

	// Give the flush a moment.
	time.Sleep(100 * time.Millisecond)

	if r := atomic.LoadInt64(&received); r != 5 {
		t.Errorf("Received %d events, want 5", r)
	}

	sent, _, batches := client.Stats()
	if sent != 5 {
		t.Errorf("Stats sent = %d, want 5", sent)
	}
	if batches != 1 {
		t.Errorf("Stats batches = %d, want 1", batches)
	}
}

func TestSIEMClient_ManualFlush(t *testing.T) {
	var received int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		atomic.AddInt64(&received, int64(len(lines)))
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := config.ExportConfig{
		SIEMEndpoint: server.URL,
		BatchSize:    100, // High threshold — won't auto-flush.
		MaxRetries:   1,
	}

	client := NewSIEMClient(cfg)
	for i := 0; i < 3; i++ {
		client.Enqueue(common.ECSEvent{SourceType: "akeso_ndr"})
	}

	// Manual flush.
	client.Flush()
	time.Sleep(50 * time.Millisecond)

	if r := atomic.LoadInt64(&received); r != 3 {
		t.Errorf("Received %d events, want 3", r)
	}
}

func TestSIEMClient_AuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer server.Close()

	cfg := config.ExportConfig{
		SIEMEndpoint: server.URL,
		BatchSize:    100,
		MaxRetries:   2,
	}

	client := NewSIEMClient(cfg)
	client.Enqueue(common.ECSEvent{SourceType: "akeso_ndr"})
	client.Flush()

	time.Sleep(50 * time.Millisecond)

	_, errors, _ := client.Stats()
	if errors != 1 {
		t.Errorf("Errors = %d, want 1 (auth failure)", errors)
	}
}

func TestSIEMClient_RetryOn503(t *testing.T) {
	var attempts int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := config.ExportConfig{
		SIEMEndpoint: server.URL,
		BatchSize:    100,
		MaxRetries:   3,
	}

	client := NewSIEMClient(cfg)
	client.Enqueue(common.ECSEvent{SourceType: "akeso_ndr"})
	client.Flush()

	time.Sleep(5 * time.Second) // Allow retries.

	if a := atomic.LoadInt64(&attempts); a < 3 {
		t.Errorf("Attempts = %d, want >= 3 (2 failures + 1 success)", a)
	}

	sent, errors, _ := client.Stats()
	if sent != 1 {
		t.Errorf("Sent = %d, want 1", sent)
	}
	if errors != 0 {
		t.Errorf("Errors = %d, want 0 (succeeded on retry)", errors)
	}
}

// ---------------------------------------------------------------------------
// P8-T2: ECS Transform Tests
// ---------------------------------------------------------------------------

func TestTransformSession_DNS(t *testing.T) {
	session := &common.SessionMeta{
		ID:        "test-session-1",
		Transport: common.TransportUDP,
		Service:   "dns",
		Flow: common.FlowKey{
			SrcIP:   net.ParseIP("10.0.0.1"),
			DstIP:   net.ParseIP("10.0.0.2"),
			SrcPort: 12345,
			DstPort: 53,
		},
		StartTime: time.Now(),
		ProtocolMeta: &common.DNSMeta{
			Query:     "example.com",
			QTypeName: "A",
			RCodeName: "NOERROR",
		},
	}

	event := TransformSession(session)

	if event.SourceType != "akeso_ndr" {
		t.Errorf("SourceType = %q, want akeso_ndr", event.SourceType)
	}
	if event.Event.Dataset != "ndr:dns" {
		t.Errorf("Dataset = %q, want ndr:dns", event.Event.Dataset)
	}
	if event.DNS != nil && event.DNS.Question.Name != "example.com" {
		t.Errorf("DNS.Question.Name = %q, want example.com", event.DNS.Question.Name)
	}

	// Verify JSON round-trip.
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Error("JSON should contain example.com")
	}
}

func TestTransformDetection(t *testing.T) {
	detection := &common.Detection{
		ID:        "det-1",
		Name:      "C2 Beacon",
		Type:      common.DetectionBeacon,
		Severity:  8,
		Certainty: 7,
		SrcIP:     "10.0.0.5",
		DstIP:     "198.51.100.1",
		MITRE: common.MITRETechnique{
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			TacticID:      "TA0011",
			TacticName:    "Command and Control",
		},
		Timestamp: time.Now(),
	}

	event := TransformDetection(detection)

	if event.Event.Kind != "alert" {
		t.Errorf("Event.Kind = %q, want alert", event.Event.Kind)
	}
	if event.Threat != nil && event.Threat.Technique.ID != "T1071" {
		t.Errorf("Threat.Technique.ID = %q, want T1071", event.Threat.Technique.ID)
	}
}

func TestTransformHostScore(t *testing.T) {
	score := &common.HostScore{
		IP:             "10.0.0.5",
		Hostname:       "workstation-5",
		ThreatScore:    75,
		CertaintyScore: 80,
		Quadrant:       common.QuadrantCritical,
	}

	event := TransformHostScore(score)

	if event.Event.Kind != "metric" {
		t.Errorf("Event.Kind = %q, want metric", event.Event.Kind)
	}
	if event.NDR.HostScore.Threat != 75 {
		t.Errorf("HostScore.Threat = %d, want 75", event.NDR.HostScore.Threat)
	}
	if event.NDR.HostScore.Certainty != 80 {
		t.Errorf("HostScore.Certainty = %d, want 80", event.NDR.HostScore.Certainty)
	}
}

// ---------------------------------------------------------------------------
// P8-T4: Host Score Export Tests
// ---------------------------------------------------------------------------

func TestHostScoreExporter_ExportsScores(t *testing.T) {
	var received int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		atomic.AddInt64(&received, int64(len(lines)))
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := config.ExportConfig{
		SIEMEndpoint: server.URL,
		BatchSize:    100,
		MaxRetries:   1,
	}
	client := NewSIEMClient(cfg)
	pipeline := NewExportPipeline(client)

	provider := func() []common.HostScore {
		return []common.HostScore{
			{IP: "10.0.0.1", ThreatScore: 50, CertaintyScore: 60, Quadrant: common.QuadrantMedium},
			{IP: "10.0.0.2", ThreatScore: 90, CertaintyScore: 85, Quadrant: common.QuadrantCritical},
		}
	}

	exporter := NewHostScoreExporter(pipeline, provider, 100*time.Millisecond)
	exporter.ExportNow()

	// Flush.
	client.Flush()
	time.Sleep(100 * time.Millisecond)

	if r := atomic.LoadInt64(&received); r != 2 {
		t.Errorf("Received %d host score events, want 2", r)
	}
}
