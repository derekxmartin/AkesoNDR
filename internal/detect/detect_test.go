package detect

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// ---------------------------------------------------------------------------
// Engine tests (P5-T1)
// ---------------------------------------------------------------------------

type mockDetector struct {
	name   string
	dtype  common.DetectionType
	alerts []*common.Detection
}

func (m *mockDetector) Name() string                        { return m.name }
func (m *mockDetector) Type() common.DetectionType          { return m.dtype }
func (m *mockDetector) ProcessSession(s *common.SessionMeta) {}
func (m *mockDetector) ProcessProtocol(meta any, p string)  {}
func (m *mockDetector) Check() []*common.Detection          { return m.alerts }

func TestEngineRegisterAndCheck(t *testing.T) {
	var mu sync.Mutex
	var received []*common.Detection

	engine := NewEngine(func(d *common.Detection) {
		mu.Lock()
		received = append(received, d)
		mu.Unlock()
	})

	mock := &mockDetector{
		name:  "test",
		dtype: common.DetectionBeacon,
		alerts: []*common.Detection{
			{ID: "alert-1", Name: "Test Alert", Type: common.DetectionBeacon,
				Severity: 5, Certainty: 7, SrcIP: "10.0.0.1"},
		},
	}
	engine.Register(mock)

	engine.Start(50 * time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	engine.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("expected at least one alert")
	}
	if received[0].ID != "alert-1" {
		t.Errorf("alert ID = %q, want alert-1", received[0].ID)
	}

	total, byType := engine.Stats()
	if total == 0 {
		t.Error("total alerts should be > 0")
	}
	if byType[common.DetectionBeacon] == 0 {
		t.Error("beacon alerts should be > 0")
	}
}

// ---------------------------------------------------------------------------
// Beacon detector tests (P5-T2)
// ---------------------------------------------------------------------------

func TestBeaconDetectorRegularTraffic(t *testing.T) {
	cfg := config.BeaconConfig{MinSessions: 10, MaxJitterRatio: 0.2}
	d := NewBeaconDetector(cfg)

	base := time.Now()
	// 15 sessions at exactly 60-second intervals → perfect beacon.
	for i := 0; i < 15; i++ {
		d.ProcessSession(&common.SessionMeta{
			Flow:      common.FlowKey{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("1.2.3.4"), DstPort: 443},
			Transport: common.TransportTCP,
			StartTime: base.Add(time.Duration(i) * 60 * time.Second),
			OrigBytes: 100, RespBytes: 200,
		})
	}

	alerts := d.Check()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 beacon alert, got %d", len(alerts))
	}
	if alerts[0].Type != common.DetectionBeacon {
		t.Errorf("type = %s, want c2_beacon", alerts[0].Type)
	}
	if alerts[0].SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q", alerts[0].SrcIP)
	}
	// Check evidence.
	cv, _ := alerts[0].Evidence["cv"].(float64)
	if cv > 0.1 {
		t.Errorf("CV = %f, expected near 0 for perfect beacon", cv)
	}
}

func TestBeaconDetectorRandomTraffic(t *testing.T) {
	cfg := config.BeaconConfig{MinSessions: 10, MaxJitterRatio: 0.2}
	d := NewBeaconDetector(cfg)

	base := time.Now()
	// Random intervals → should NOT alert.
	intervals := []int{5, 120, 3, 300, 15, 45, 200, 8, 90, 600, 12, 35}
	offset := 0
	for _, iv := range intervals {
		offset += iv
		d.ProcessSession(&common.SessionMeta{
			Flow:      common.FlowKey{SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("5.6.7.8"), DstPort: 80},
			Transport: common.TransportTCP,
			StartTime: base.Add(time.Duration(offset) * time.Second),
			OrigBytes: 50, RespBytes: 500,
		})
	}

	alerts := d.Check()
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for random traffic, got %d", len(alerts))
	}
}

func TestBeaconDetectorBelowMinSessions(t *testing.T) {
	cfg := config.BeaconConfig{MinSessions: 10, MaxJitterRatio: 0.2}
	d := NewBeaconDetector(cfg)

	// Only 5 sessions — below threshold.
	for i := 0; i < 5; i++ {
		d.ProcessSession(&common.SessionMeta{
			Flow:      common.FlowKey{SrcIP: net.ParseIP("10.0.0.3"), DstIP: net.ParseIP("9.9.9.9"), DstPort: 443},
			Transport: common.TransportTCP,
			StartTime: time.Now().Add(time.Duration(i) * 60 * time.Second),
		})
	}

	alerts := d.Check()
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts below min_sessions, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// DNS tunnel detector tests (P5-T3)
// ---------------------------------------------------------------------------

func TestDNSTunnelHighEntropy(t *testing.T) {
	cfg := config.DNSTunnelConfig{EntropyThreshold: 3.5, QueryVolumeThreshold: 15, MaxSubdomainDepth: 3}
	d := NewDNSTunnelDetector(cfg)

	// Simulate high-entropy DNS queries (tunneling pattern).
	for i := 0; i < 20; i++ {
		d.ProcessProtocol(&common.DNSMeta{
			Query:          fmt.Sprintf("aGVsbG8gd29ybGQ%d.tunnel.evil.com", i),
			QTypeName:      "TXT",
			RCodeName:      "NOERROR",
			Entropy:        4.2,
			SubdomainDepth: 4,
			QueryLength:    40,
		}, "dns")
	}

	alerts := d.Check()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 DNS tunnel alert, got %d", len(alerts))
	}
	if alerts[0].Type != common.DetectionDNSTunnel {
		t.Errorf("type = %s", alerts[0].Type)
	}
}

func TestDNSTunnelNormalTraffic(t *testing.T) {
	cfg := config.DNSTunnelConfig{EntropyThreshold: 3.5, QueryVolumeThreshold: 100, MaxSubdomainDepth: 5}
	d := NewDNSTunnelDetector(cfg)

	// Normal DNS queries — low entropy, low depth.
	domains := []string{"google.com", "example.com", "github.com"}
	for i := 0; i < 30; i++ {
		d.ProcessProtocol(&common.DNSMeta{
			Query:          "www." + domains[i%3],
			QTypeName:      "A",
			RCodeName:      "NOERROR",
			Entropy:        2.5,
			SubdomainDepth: 2,
			QueryLength:    15,
		}, "dns")
	}

	alerts := d.Check()
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for normal DNS, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// Lateral movement detector tests (P5-T4)
// ---------------------------------------------------------------------------

func TestLateralMovementFanOut(t *testing.T) {
	cfg := config.LateralMoveConfig{FanOutThreshold: 3}
	d := NewLateralMovementDetector(cfg)

	// Source connecting to 5 different internal hosts via SMB.
	for i := 0; i < 5; i++ {
		d.ProcessSession(&common.SessionMeta{
			Flow: common.FlowKey{
				SrcIP:   net.ParseIP("10.0.0.1"),
				DstIP:   net.ParseIP(fmt.Sprintf("10.0.0.%d", 10+i)),
				DstPort: 445,
			},
			Transport: common.TransportTCP,
		})
	}

	alerts := d.Check()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 lateral movement alert, got %d", len(alerts))
	}
	if alerts[0].Type != common.DetectionLateralMovement {
		t.Errorf("type = %s", alerts[0].Type)
	}
	fanOut, _ := alerts[0].Evidence["fan_out"].(int)
	if fanOut != 5 {
		t.Errorf("fan_out = %d, want 5", fanOut)
	}
}

func TestLateralMovementBelowThreshold(t *testing.T) {
	cfg := config.LateralMoveConfig{FanOutThreshold: 5}
	d := NewLateralMovementDetector(cfg)

	// Only 2 destinations — below threshold.
	for i := 0; i < 2; i++ {
		d.ProcessSession(&common.SessionMeta{
			Flow: common.FlowKey{
				SrcIP:   net.ParseIP("10.0.0.2"),
				DstIP:   net.ParseIP(fmt.Sprintf("10.0.0.%d", 20+i)),
				DstPort: 445,
			},
			Transport: common.TransportTCP,
		})
	}

	alerts := d.Check()
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts below threshold, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// Exfiltration detector tests (P5-T5)
// ---------------------------------------------------------------------------

func TestExfilDetectorHighVolume(t *testing.T) {
	cfg := config.ExfilConfig{DeviationThreshold: 3.0, AbsoluteThresholdMB: 1}
	d := NewExfilDetector(cfg)

	// Build a baseline: 10 check intervals of ~100KB.
	for i := 0; i < 10; i++ {
		d.ProcessSession(&common.SessionMeta{
			Flow:      common.FlowKey{SrcIP: net.ParseIP("10.0.0.1")},
			Transport: common.TransportTCP,
			OrigBytes: 100 * 1024, // 100KB
		})
		d.Check() // Advance window.
	}

	// Now a massive spike: 10MB.
	d.ProcessSession(&common.SessionMeta{
		Flow:      common.FlowKey{SrcIP: net.ParseIP("10.0.0.1")},
		Transport: common.TransportTCP,
		OrigBytes: 10 * 1024 * 1024,
	})

	alerts := d.Check()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 exfil alert, got %d", len(alerts))
	}
	if alerts[0].Type != common.DetectionExfiltration {
		t.Errorf("type = %s", alerts[0].Type)
	}
}

func TestExfilDetectorNormalTraffic(t *testing.T) {
	cfg := config.ExfilConfig{DeviationThreshold: 3.0, AbsoluteThresholdMB: 500}
	d := NewExfilDetector(cfg)

	// Consistent low traffic.
	for i := 0; i < 10; i++ {
		d.ProcessSession(&common.SessionMeta{
			Flow:      common.FlowKey{SrcIP: net.ParseIP("10.0.0.2")},
			Transport: common.TransportTCP,
			OrigBytes: 50 * 1024,
		})
		alerts := d.Check()
		if len(alerts) != 0 {
			t.Errorf("check %d: expected 0 alerts for normal traffic, got %d", i, len(alerts))
		}
	}
}
