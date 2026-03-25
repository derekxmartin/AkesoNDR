package sessions

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func defaultCfg() config.SessionsConfig {
	return config.SessionsConfig{
		TCPTimeout:      config.Duration(5 * time.Minute),
		UDPTimeout:      config.Duration(2 * time.Minute),
		MaxConcurrent:   10000,
		CleanupInterval: config.Duration(100 * time.Millisecond),
	}
}

type collectedSession struct {
	mu       sync.Mutex
	sessions []*common.SessionMeta
}

func (c *collectedSession) callback(s *common.SessionMeta) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = append(c.sessions, s)
}

func (c *collectedSession) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}

func (c *collectedSession) get(i int) *common.SessionMeta {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[i]
}

// ---------------------------------------------------------------------------
// conn_state FSM tests
// ---------------------------------------------------------------------------

func TestConnState_S0(t *testing.T) {
	f := &tcpFlags{origSYN: true}
	if got := connState(f); got != common.ConnStateS0 {
		t.Errorf("expected S0, got %s", got)
	}
}

func TestConnState_S1(t *testing.T) {
	f := &tcpFlags{origSYN: true, respSYN: true}
	if got := connState(f); got != common.ConnStateS1 {
		t.Errorf("expected S1, got %s", got)
	}
}

func TestConnState_SF(t *testing.T) {
	f := &tcpFlags{origSYN: true, respSYN: true, origFIN: true, respFIN: true}
	if got := connState(f); got != common.ConnStateSF {
		t.Errorf("expected SF, got %s", got)
	}
}

func TestConnState_REJ(t *testing.T) {
	f := &tcpFlags{origSYN: true, respRST: true}
	if got := connState(f); got != common.ConnStateREJ {
		t.Errorf("expected REJ, got %s", got)
	}
}

func TestConnState_RSTO(t *testing.T) {
	f := &tcpFlags{origSYN: true, respSYN: true, origRST: true}
	if got := connState(f); got != common.ConnStateRSTO {
		t.Errorf("expected RSTO, got %s", got)
	}
}

func TestConnState_RSTR(t *testing.T) {
	f := &tcpFlags{origSYN: true, respSYN: true, respRST: true}
	if got := connState(f); got != common.ConnStateRSTR {
		t.Errorf("expected RSTR, got %s", got)
	}
}

func TestConnState_S2(t *testing.T) {
	f := &tcpFlags{origSYN: true, respSYN: true, origFIN: true}
	if got := connState(f); got != common.ConnStateS2 {
		t.Errorf("expected S2, got %s", got)
	}
}

func TestConnState_S3(t *testing.T) {
	f := &tcpFlags{origSYN: true, respSYN: true, respFIN: true}
	if got := connState(f); got != common.ConnStateS3 {
		t.Errorf("expected S3, got %s", got)
	}
}

func TestConnState_OTH(t *testing.T) {
	f := &tcpFlags{origData: true, respData: true}
	if got := connState(f); got != common.ConnStateOTH {
		t.Errorf("expected OTH, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// Tracker integration tests
// ---------------------------------------------------------------------------

func TestTracker_TCPSession(t *testing.T) {
	pcapPath := writeHTTPPCAP(t)
	collected := &collectedSession{}
	tracker := NewTracker(defaultCfg(), collected.callback)

	replayPCAP(t, pcapPath, func(pkt gopacket.Packet) {
		tracker.TrackPacket(pkt)
	})

	// Give async close goroutine time to clean up.
	time.Sleep(50 * time.Millisecond)

	if collected.count() == 0 {
		t.Fatal("expected at least 1 closed session")
	}

	s := collected.get(0)
	t.Logf("Session: %s state=%s duration=%v orig_bytes=%d resp_bytes=%d orig_pkts=%d resp_pkts=%d",
		s.ID, s.ConnState, s.Duration, s.OrigBytes, s.RespBytes, s.OrigPackets, s.RespPackets)

	if s.ConnState != common.ConnStateSF {
		t.Errorf("conn_state: got %s, want SF", s.ConnState)
	}
	if s.Duration <= 0 {
		t.Errorf("duration should be > 0, got %v", s.Duration)
	}
	if s.OrigPackets == 0 {
		t.Error("orig_packets should be > 0")
	}
	if s.RespPackets == 0 {
		t.Error("resp_packets should be > 0")
	}
	if s.OrigBytes == 0 {
		t.Error("orig_bytes should be > 0")
	}
	if s.RespBytes == 0 {
		t.Error("resp_bytes should be > 0")
	}
	if s.Transport != common.TransportTCP {
		t.Errorf("transport: got %s, want tcp", s.Transport)
	}
}

func TestTracker_UDPSession_Timeout(t *testing.T) {
	cfg := defaultCfg()
	cfg.UDPTimeout = config.Duration(100 * time.Millisecond)
	cfg.CleanupInterval = config.Duration(50 * time.Millisecond)

	collected := &collectedSession{}
	tracker := NewTracker(cfg, collected.callback)
	tracker.StartCleanup()

	// Feed a single UDP packet.
	pkt := buildUDPGopacket(t, 10, 0, 0, 100, 53)
	tracker.TrackPacket(pkt)

	if tracker.ActiveSessions() != 1 {
		t.Errorf("active sessions: got %d, want 1", tracker.ActiveSessions())
	}

	// Wait for timeout + sweep.
	time.Sleep(300 * time.Millisecond)

	if tracker.ActiveSessions() != 0 {
		t.Errorf("active sessions after timeout: got %d, want 0", tracker.ActiveSessions())
	}
	if collected.count() == 0 {
		t.Error("expected timeout callback for stale UDP session")
	}

	tracker.Stop()
	t.Logf("UDP session timed out after sweep, collected=%d", collected.count())
}

func TestTracker_RSTClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rst.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	ts := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	srcMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := []byte{10, 0, 0, 100}
	dstIP := []byte{10, 0, 0, 5}

	// SYN
	writeTCPPkt(t, w, srcMAC, dstMAC, srcIP, dstIP, 50000, 80, 1000, 0, true, false, false, false, false, nil, ts)
	// SYN-ACK
	writeTCPPkt(t, w, dstMAC, srcMAC, dstIP, srcIP, 80, 50000, 2000, 1001, false, true, true, false, false, nil, ts.Add(time.Millisecond))
	// RST from originator
	writeTCPPkt(t, w, srcMAC, dstMAC, srcIP, dstIP, 50000, 80, 1001, 2001, false, false, false, false, true, nil, ts.Add(2*time.Millisecond))

	f.Close()

	collected := &collectedSession{}
	tracker := NewTracker(defaultCfg(), collected.callback)

	replayPCAP(t, path, func(pkt gopacket.Packet) {
		tracker.TrackPacket(pkt)
	})

	time.Sleep(50 * time.Millisecond)

	if collected.count() == 0 {
		t.Fatal("expected RST-closed session")
	}
	if collected.get(0).ConnState != common.ConnStateRSTO {
		t.Errorf("conn_state: got %s, want RSTO", collected.get(0).ConnState)
	}
}

func TestTracker_StopClosesRemaining(t *testing.T) {
	collected := &collectedSession{}
	tracker := NewTracker(defaultCfg(), collected.callback)

	// Feed a SYN-only — session stays open.
	pkt := buildTCPGopacket(t, 100, 5, 50000, 80, true, false, false, false, false, nil)
	tracker.TrackPacket(pkt)

	if tracker.ActiveSessions() != 1 {
		t.Fatalf("expected 1 active session, got %d", tracker.ActiveSessions())
	}

	tracker.Stop()

	if collected.count() == 0 {
		t.Error("expected Stop() to finalize remaining sessions")
	}
}

func TestTracker_Stats(t *testing.T) {
	pcapPath := writeHTTPPCAP(t)
	collected := &collectedSession{}
	tracker := NewTracker(defaultCfg(), collected.callback)

	replayPCAP(t, pcapPath, func(pkt gopacket.Packet) {
		tracker.TrackPacket(pkt)
	})

	time.Sleep(50 * time.Millisecond)

	created, closed := tracker.Stats()
	if created == 0 {
		t.Error("totalCreated should be > 0")
	}
	if closed == 0 {
		t.Error("totalClosed should be > 0")
	}
	t.Logf("Stats: created=%d closed=%d", created, closed)
}

// ---------------------------------------------------------------------------
// Packet & PCAP builders
// ---------------------------------------------------------------------------

func buildUDPGopacket(t *testing.T, srcIPLast, dstIPLast byte, srcPort, dstPort int, dnsPort int) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: []byte{10, 0, 0, srcIPLast}, DstIP: []byte{8, 8, 8, dstIPLast},
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dnsPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("test")))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	pkt.Metadata().CaptureInfo.Length = len(buf.Bytes())
	return pkt
}

func buildTCPGopacket(t *testing.T, srcIPLast, dstIPLast byte,
	srcPort, dstPort int,
	syn, synack, ack, fin, rst bool, payload []byte,
) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: []byte{10, 0, 0, srcIPLast}, DstIP: []byte{10, 0, 0, dstIPLast},
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort),
		SYN: syn, ACK: synack || ack, FIN: fin, RST: rst,
		Seq: 1000, Window: 65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ls := []gopacket.SerializableLayer{eth, ip, tcp}
	if len(payload) > 0 {
		ls = append(ls, gopacket.Payload(payload))
	}
	gopacket.SerializeLayers(buf, opts, ls...)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	pkt.Metadata().CaptureInfo.Length = len(buf.Bytes())
	return pkt
}

func writeHTTPPCAP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "http.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	ts := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	srcMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := []byte{10, 0, 0, 100}
	dstIP := []byte{93, 184, 216, 34}

	seq, ack := uint32(1000), uint32(0)

	// SYN
	writeTCPPkt(t, w, srcMAC, dstMAC, srcIP, dstIP, 54321, 80, seq, ack, true, false, false, false, false, nil, ts)
	seq++
	ts = ts.Add(time.Millisecond)
	// SYN-ACK
	sSeq := uint32(2000)
	writeTCPPkt(t, w, dstMAC, srcMAC, dstIP, srcIP, 80, 54321, sSeq, seq, false, true, true, false, false, nil, ts)
	sSeq++
	ts = ts.Add(time.Millisecond)
	// ACK
	writeTCPPkt(t, w, srcMAC, dstMAC, srcIP, dstIP, 54321, 80, seq, sSeq, false, false, true, false, false, nil, ts)
	ts = ts.Add(time.Millisecond)
	// HTTP request
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	writeTCPPkt(t, w, srcMAC, dstMAC, srcIP, dstIP, 54321, 80, seq, sSeq, false, false, true, false, false, req, ts)
	seq += uint32(len(req))
	ts = ts.Add(time.Millisecond)
	// HTTP response
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	writeTCPPkt(t, w, dstMAC, srcMAC, dstIP, srcIP, 80, 54321, sSeq, seq, false, false, true, false, false, resp, ts)
	sSeq += uint32(len(resp))
	ts = ts.Add(time.Millisecond)
	// FIN
	writeTCPPkt(t, w, srcMAC, dstMAC, srcIP, dstIP, 54321, 80, seq, sSeq, false, false, true, true, false, nil, ts)
	seq++
	ts = ts.Add(time.Millisecond)
	// FIN-ACK
	writeTCPPkt(t, w, dstMAC, srcMAC, dstIP, srcIP, 80, 54321, sSeq, seq, false, false, true, true, false, nil, ts)

	f.Close()
	return path
}

func writeTCPPkt(t *testing.T, w *pcapgo.Writer,
	srcMAC, dstMAC, srcIP, dstIP []byte,
	srcPort, dstPort int, seq, ack uint32,
	syn, synack, ackFlag, fin, rst bool, payload []byte, ts time.Time,
) {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort),
		Seq: seq, Ack: ack,
		SYN: syn || synack, ACK: synack || ackFlag || fin, FIN: fin, RST: rst, PSH: len(payload) > 0,
		Window: 65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ls := []gopacket.SerializableLayer{eth, ip, tcp}
	if len(payload) > 0 {
		ls = append(ls, gopacket.Payload(payload))
	}
	gopacket.SerializeLayers(buf, opts, ls...)

	raw := buf.Bytes()
	w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(raw), Length: len(raw)}, raw)
}

func replayPCAP(t *testing.T, path string, fn func(gopacket.Packet)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	source := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
	for pkt := range source.Packets() {
		fn(pkt)
	}
}
