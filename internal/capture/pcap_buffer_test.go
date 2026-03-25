package capture

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/akesondr/akeso-ndr/internal/config"
)

// buildTestPacket creates a minimal Ethernet/IPv4/TCP packet for testing.
func buildTestPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ts time.Time) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true})
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}
	return pkt
}

// buildUDPTestPacket creates a minimal Ethernet/IPv4/UDP packet.
func buildUDPTestPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ts time.Time) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true})
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}
	return pkt
}

func testBufferConfig(dir string, maxSizeMB int) config.PcapBufferConfig {
	return config.PcapBufferConfig{
		MaxSizeMB:      maxSizeMB,
		Retention:       config.Duration(30 * time.Minute),
		StoragePath:    dir,
		MaxFlowPackets: 50,
	}
}

func TestPcapBufferWriteAndStats(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewPcapBuffer(testBufferConfig(dir, 100))
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	flowKey := "10.0.0.1:12345-10.0.0.2:80/6"

	// Write 10 packets.
	for i := 0; i < 10; i++ {
		pkt := buildTestPacket("10.0.0.1", "10.0.0.2", 12345, 80,
			[]byte("hello"), ts.Add(time.Duration(i)*time.Second))
		if err := buf.WritePacket(pkt, flowKey); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
	}

	totalBytes, segments, flows := buf.Stats()
	if totalBytes <= 0 {
		t.Errorf("totalBytes should be > 0, got %d", totalBytes)
	}
	if segments != 1 {
		t.Errorf("expected 1 segment, got %d", segments)
	}
	if flows != 1 {
		t.Errorf("expected 1 flow, got %d", flows)
	}
}

func TestPcapBufferExtractProducesValidPCAP(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewPcapBuffer(testBufferConfig(dir, 100))
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	flowKey := "10.0.0.1:12345-10.0.0.2:80/6"

	// Write 5 packets.
	for i := 0; i < 5; i++ {
		pkt := buildTestPacket("10.0.0.1", "10.0.0.2", 12345, 80,
			[]byte("data"), ts.Add(time.Duration(i)*time.Second))
		if err := buf.WritePacket(pkt, flowKey); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}

	// Extract all packets.
	outPath := filepath.Join(dir, "extracted.pcap")
	n, err := buf.ExtractFlow(flowKey, ts, ts.Add(5*time.Second), outPath)
	if err != nil {
		t.Fatalf("ExtractFlow: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 extracted packets, got %d", n)
	}

	// Verify the output is a valid PCAP with the correct packet count.
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open extracted: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}

	count := 0
	for {
		_, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadPacketData: %v", err)
		}
		count++
	}
	if count != 5 {
		t.Errorf("extracted PCAP has %d packets, want 5", count)
	}
}

func TestPcapBufferExtractTimeRange(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewPcapBuffer(testBufferConfig(dir, 100))
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	flowKey := "10.0.0.1:12345-10.0.0.2:80/6"

	// Write 10 packets, 1 second apart.
	for i := 0; i < 10; i++ {
		pkt := buildTestPacket("10.0.0.1", "10.0.0.2", 12345, 80,
			[]byte("x"), ts.Add(time.Duration(i)*time.Second))
		if err := buf.WritePacket(pkt, flowKey); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}

	// Extract only packets in [ts+2s, ts+5s] → should get 4 packets (indices 2,3,4,5).
	outPath := filepath.Join(dir, "range.pcap")
	n, err := buf.ExtractFlow(flowKey, ts.Add(2*time.Second), ts.Add(5*time.Second), outPath)
	if err != nil {
		t.Fatalf("ExtractFlow: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 packets in time range, got %d", n)
	}
}

func TestPcapBufferMultipleFlows(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewPcapBuffer(testBufferConfig(dir, 100))
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	flow1 := "10.0.0.1:12345-10.0.0.2:80/6"
	flow2 := "10.0.0.1:54321-10.0.0.3:443/6"

	// Write 5 packets for each flow interleaved.
	for i := 0; i < 5; i++ {
		pkt1 := buildTestPacket("10.0.0.1", "10.0.0.2", 12345, 80,
			[]byte("flow1"), ts.Add(time.Duration(i)*time.Second))
		pkt2 := buildTestPacket("10.0.0.1", "10.0.0.3", 54321, 443,
			[]byte("flow2"), ts.Add(time.Duration(i)*time.Second))
		buf.WritePacket(pkt1, flow1)
		buf.WritePacket(pkt2, flow2)
	}

	_, _, flows := buf.Stats()
	if flows != 2 {
		t.Errorf("expected 2 flows, got %d", flows)
	}

	// Extract flow1 — should only get flow1 packets.
	out1 := filepath.Join(dir, "flow1.pcap")
	n, err := buf.ExtractFlow(flow1, ts, ts.Add(10*time.Second), out1)
	if err != nil {
		t.Fatalf("ExtractFlow flow1: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 packets for flow1, got %d", n)
	}

	// Extract flow2.
	out2 := filepath.Join(dir, "flow2.pcap")
	n, err = buf.ExtractFlow(flow2, ts, ts.Add(10*time.Second), out2)
	if err != nil {
		t.Fatalf("ExtractFlow flow2: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 packets for flow2, got %d", n)
	}
}

func TestPcapBufferMaxFlowPackets(t *testing.T) {
	dir := t.TempDir()
	cfg := testBufferConfig(dir, 100)
	cfg.MaxFlowPackets = 5 // Only keep 5 per flow.
	buf, err := NewPcapBuffer(cfg)
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	flowKey := "10.0.0.1:12345-10.0.0.2:80/6"

	// Write 20 packets — only first 5 should be stored.
	for i := 0; i < 20; i++ {
		pkt := buildTestPacket("10.0.0.1", "10.0.0.2", 12345, 80,
			[]byte("data"), ts.Add(time.Duration(i)*time.Second))
		buf.WritePacket(pkt, flowKey)
	}

	outPath := filepath.Join(dir, "capped.pcap")
	n, err := buf.ExtractFlow(flowKey, ts, ts.Add(30*time.Second), outPath)
	if err != nil {
		t.Fatalf("ExtractFlow: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 packets (capped), got %d", n)
	}
}

func TestPcapBufferEviction(t *testing.T) {
	dir := t.TempDir()
	// Set max to 1 MB — very small to force eviction.
	cfg := testBufferConfig(dir, 1)
	cfg.MaxFlowPackets = 100000 // No per-flow limit.
	buf, err := NewPcapBuffer(cfg)
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	ts := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	flowKey := "10.0.0.1:12345-10.0.0.2:80/6"

	// Write a large number of packets to exceed 1 MB.
	bigPayload := make([]byte, 1024) // 1KB per packet
	for i := 0; i < 2000; i++ {
		pkt := buildTestPacket("10.0.0.1", "10.0.0.2", 12345, 80,
			bigPayload, ts.Add(time.Duration(i)*time.Millisecond))
		buf.WritePacket(pkt, flowKey)
	}

	totalBytes, _, _ := buf.Stats()
	maxBytes := int64(cfg.MaxSizeMB) * 1024 * 1024

	// Total should be at or below max (with one segment tolerance).
	if totalBytes > maxBytes+segmentMaxBytes {
		t.Errorf("totalBytes %d exceeds max %d + segment overhead", totalBytes, maxBytes)
	}

	// Verify segment files on disk — old ones should be deleted.
	files, _ := filepath.Glob(filepath.Join(dir, "buffer_*.pcap"))
	if len(files) == 0 {
		t.Error("no segment files on disk")
	}
}

func TestPcapBufferExtractNonexistentFlow(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewPcapBuffer(testBufferConfig(dir, 100))
	if err != nil {
		t.Fatalf("NewPcapBuffer: %v", err)
	}
	defer buf.Close()

	_, err = buf.ExtractFlow("nonexistent", time.Now(), time.Now(), filepath.Join(dir, "out.pcap"))
	if err == nil {
		t.Error("expected error for nonexistent flow, got nil")
	}
}
