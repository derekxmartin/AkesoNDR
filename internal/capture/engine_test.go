package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/akesondr/akeso-ndr/internal/config"
)

// writeSamplePCAP creates a small PCAP file with the given number of
// synthetic Ethernet/IP/UDP packets and returns its path.
func writeSamplePCAP(t *testing.T, numPackets int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	for i := range numPackets {
		pkt := buildUDPPacket(t, i)
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now().Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(pkt),
			Length:        len(pkt),
		}
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	return path
}

// buildUDPPacket creates a raw serialized Ethernet/IP/UDP packet.
func buildUDPPacket(t *testing.T, seq int) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{10, 0, 0, 100},
		DstIP:    []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345 + seq%100),
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)
	payload := []byte("test-payload")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return buf.Bytes()
}

func TestEngine_OfflineReplay(t *testing.T) {
	pcapPath := writeSamplePCAP(t, 50)

	cfg := config.CaptureConfig{
		SnapLen: 65535,
	}

	engine := NewEngine(cfg, pcapPath, 100)
	if err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	var count int
	for range engine.Packets() {
		count++
	}

	// Packets channel is closed when replay finishes — no need to Stop().
	m := engine.GetMetrics()

	if count != 50 {
		t.Errorf("packets received: got %d, want 50", count)
	}
	if m.PacketsReceived != 50 {
		t.Errorf("metrics.PacketsReceived: got %d, want 50", m.PacketsReceived)
	}
	if m.BytesReceived == 0 {
		t.Error("metrics.BytesReceived should be > 0")
	}
}

func TestEngine_OfflineReplay_Metrics(t *testing.T) {
	pcapPath := writeSamplePCAP(t, 100)

	cfg := config.CaptureConfig{SnapLen: 65535}
	engine := NewEngine(cfg, pcapPath, 200)
	if err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	for range engine.Packets() {
	}

	m := engine.GetMetrics()

	if m.PacketsReceived != 100 {
		t.Errorf("PacketsReceived: got %d, want 100", m.PacketsReceived)
	}
	if m.BytesReceived == 0 {
		t.Error("BytesReceived should be > 0")
	}
	if m.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
	// PPS/BPS may be Inf or very large for fast offline replays — just log.
	t.Logf("Replay: packets=%d bytes=%d pps=%.0f bps=%.0f",
		m.PacketsReceived, m.BytesReceived, m.PPS(), m.BPS())
}

func TestEngine_OfflineReplay_EmptyPCAP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	f.Close()

	cfg := config.CaptureConfig{SnapLen: 65535}
	engine := NewEngine(cfg, path, 10)
	if err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	count := 0
	for range engine.Packets() {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 packets from empty pcap, got %d", count)
	}
}

func TestEngine_StopDuringCapture(t *testing.T) {
	// Write a large PCAP so we can stop mid-stream.
	pcapPath := writeSamplePCAP(t, 10000)

	cfg := config.CaptureConfig{SnapLen: 65535}
	engine := NewEngine(cfg, pcapPath, 100)
	if err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Read a few packets then stop.
	count := 0
	for range engine.Packets() {
		count++
		if count >= 50 {
			engine.Stop()
			break
		}
	}

	// We should have gotten at least 50 but less than 10000.
	if count < 50 {
		t.Errorf("expected at least 50 packets, got %d", count)
	}
	if count >= 10000 {
		t.Errorf("expected Stop() to halt capture, but got all %d packets", count)
	}
	t.Logf("Stopped after %d packets", count)
}

func TestEngine_InvalidPCAPFile(t *testing.T) {
	cfg := config.CaptureConfig{SnapLen: 65535}
	engine := NewEngine(cfg, "/nonexistent/file.pcap", 10)
	err := engine.Start()
	if err == nil {
		t.Fatal("expected error for nonexistent PCAP file")
	}
	t.Logf("got expected error: %v", err)
}
