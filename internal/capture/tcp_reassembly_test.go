package capture

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ---------------------------------------------------------------------------
// Test handler — collects dispatched streams
// ---------------------------------------------------------------------------

type testStreamHandler struct {
	mu      sync.Mutex
	streams []capturedStream
}

type capturedStream struct {
	net, transport gopacket.Flow
	client, server []byte
}

func (h *testStreamHandler) HandleStream(net, transport gopacket.Flow, client, server []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streams = append(h.streams, capturedStream{
		net: net, transport: transport,
		client: append([]byte(nil), client...),
		server: append([]byte(nil), server...),
	})
}

func (h *testStreamHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.streams)
}

// ---------------------------------------------------------------------------
// PCAP builder helpers
// ---------------------------------------------------------------------------

type tcpState struct {
	clientSeq, serverSeq uint32
}

func writeHTTPSessionPCAP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "http.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	srcMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := []byte{10, 0, 0, 100}
	dstIP := []byte{93, 184, 216, 34}
	srcPort := layers.TCPPort(54321)
	dstPort := layers.TCPPort(80)
	ts := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)

	st := &tcpState{clientSeq: 1000, serverSeq: 2000}

	// SYN
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort,
		st.clientSeq, 0, true, false, false, false, nil, ts)
	st.clientSeq++
	ts = ts.Add(time.Millisecond)

	// SYN-ACK
	writeTCPPacket(t, w, dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort,
		st.serverSeq, st.clientSeq, true, true, false, false, nil, ts)
	st.serverSeq++
	ts = ts.Add(time.Millisecond)

	// ACK
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort,
		st.clientSeq, st.serverSeq, false, true, false, false, nil, ts)
	ts = ts.Add(time.Millisecond)

	// HTTP GET request
	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: AkesoNDR-Test/1.0\r\n\r\n")
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort,
		st.clientSeq, st.serverSeq, false, true, true, false, httpReq, ts)
	st.clientSeq += uint32(len(httpReq))
	ts = ts.Add(time.Millisecond)

	// HTTP response
	httpResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!")
	writeTCPPacket(t, w, dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort,
		st.serverSeq, st.clientSeq, false, true, true, false, httpResp, ts)
	st.serverSeq += uint32(len(httpResp))
	ts = ts.Add(time.Millisecond)

	// FIN from client
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort,
		st.clientSeq, st.serverSeq, false, true, false, true, nil, ts)
	st.clientSeq++
	ts = ts.Add(time.Millisecond)

	// FIN-ACK from server
	writeTCPPacket(t, w, dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort,
		st.serverSeq, st.clientSeq, false, true, false, true, nil, ts)

	return path
}

func writeTCPPacket(t *testing.T, w *pcapgo.Writer,
	srcMAC, dstMAC, srcIP, dstIP []byte,
	srcPort, dstPort layers.TCPPort,
	seq, ack uint32,
	syn, ackFlag, psh, fin bool,
	payload []byte, ts time.Time,
) {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: srcMAC, DstMAC: dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP, DstIP: dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort, DstPort: dstPort,
		Seq: seq, Ack: ack,
		SYN: syn, ACK: ackFlag, PSH: psh, FIN: fin,
		Window: 65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	serializeLayers := []gopacket.SerializableLayer{eth, ip, tcp}
	if len(payload) > 0 {
		serializeLayers = append(serializeLayers, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		t.Fatalf("serialize TCP packet: %v", err)
	}

	raw := buf.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(raw),
		Length:        len(raw),
	}
	if err := w.WritePacket(ci, raw); err != nil {
		t.Fatalf("write TCP packet: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestAssembler_HTTPBidirectional(t *testing.T) {
	pcapPath := writeHTTPSessionPCAP(t)
	handler := &testStreamHandler{}
	asm := NewAssembler(handler)

	// Replay the PCAP through the assembler.
	f, err := os.Open(pcapPath)
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
		asm.ProcessPacket(pkt)
	}
	asm.FlushAll()

	if handler.count() == 0 {
		t.Fatal("expected at least 1 reassembled stream, got 0")
	}

	s := handler.streams[0]
	clientStr := string(s.client)
	serverStr := string(s.server)

	t.Logf("Client data (%d bytes): %q", len(s.client), clientStr)
	t.Logf("Server data (%d bytes): %q", len(s.server), serverStr)

	// Verify HTTP request was reassembled.
	if !strings.Contains(clientStr, "GET / HTTP/1.1") {
		t.Errorf("client stream should contain HTTP GET request, got: %q", clientStr)
	}
	if !strings.Contains(clientStr, "Host: example.com") {
		t.Errorf("client stream should contain Host header, got: %q", clientStr)
	}

	// Verify HTTP response was reassembled.
	if !strings.Contains(serverStr, "HTTP/1.1 200 OK") {
		t.Errorf("server stream should contain HTTP 200 response, got: %q", serverStr)
	}
	if !strings.Contains(serverStr, "Hello, World!") {
		t.Errorf("server stream should contain response body, got: %q", serverStr)
	}
}

func TestAssembler_MultipleStreams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	mac1 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	mac2 := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	ts := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)

	// Stream 1: 10.0.0.100:54321 → 93.184.216.34:80
	writeSimpleTCPExchange(t, w, mac1, mac2,
		[]byte{10, 0, 0, 100}, []byte{93, 184, 216, 34},
		54321, 80, []byte("REQ1"), []byte("RESP1"), ts)

	// Stream 2: 10.0.0.101:54322 → 93.184.216.34:443
	writeSimpleTCPExchange(t, w, mac1, mac2,
		[]byte{10, 0, 0, 101}, []byte{93, 184, 216, 34},
		54322, 443, []byte("REQ2"), []byte("RESP2"), ts.Add(10*time.Millisecond))

	f.Close()

	handler := &testStreamHandler{}
	asm := NewAssembler(handler)

	rf, _ := os.Open(path)
	defer rf.Close()
	reader, _ := pcapgo.NewReader(rf)
	source := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)

	for pkt := range source.Packets() {
		asm.ProcessPacket(pkt)
	}
	asm.FlushAll()

	if handler.count() < 2 {
		t.Errorf("expected at least 2 streams, got %d", handler.count())
	}
	t.Logf("Reassembled %d streams", handler.count())
}

func TestAssembler_IgnoresUDP(t *testing.T) {
	// Build a PCAP with only UDP packets — assembler should produce 0 streams.
	pcapPath := writeSamplePCAP(t, 10) // from engine_test.go — UDP packets

	handler := &testStreamHandler{}
	asm := NewAssembler(handler)

	f, _ := os.Open(pcapPath)
	defer f.Close()
	reader, _ := pcapgo.NewReader(f)
	source := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)

	for pkt := range source.Packets() {
		asm.ProcessPacket(pkt)
	}
	asm.FlushAll()

	if handler.count() != 0 {
		t.Errorf("expected 0 streams for UDP-only PCAP, got %d", handler.count())
	}
}

// writeSimpleTCPExchange writes a minimal SYN/SYN-ACK/data/FIN exchange.
func writeSimpleTCPExchange(t *testing.T, w *pcapgo.Writer,
	srcMAC, dstMAC, srcIP, dstIP []byte,
	srcPort, dstPort int, reqPayload, respPayload []byte, ts time.Time,
) {
	t.Helper()
	sp := layers.TCPPort(srcPort)
	dp := layers.TCPPort(dstPort)
	cSeq := uint32(1000)
	sSeq := uint32(2000)

	// SYN
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, sp, dp, cSeq, 0, true, false, false, false, nil, ts)
	cSeq++
	ts = ts.Add(time.Millisecond)

	// SYN-ACK
	writeTCPPacket(t, w, dstMAC, srcMAC, dstIP, srcIP, dp, sp, sSeq, cSeq, true, true, false, false, nil, ts)
	sSeq++
	ts = ts.Add(time.Millisecond)

	// ACK
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, sp, dp, cSeq, sSeq, false, true, false, false, nil, ts)
	ts = ts.Add(time.Millisecond)

	// Request data
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, sp, dp, cSeq, sSeq, false, true, true, false, reqPayload, ts)
	cSeq += uint32(len(reqPayload))
	ts = ts.Add(time.Millisecond)

	// Response data
	writeTCPPacket(t, w, dstMAC, srcMAC, dstIP, srcIP, dp, sp, sSeq, cSeq, false, true, true, false, respPayload, ts)
	sSeq += uint32(len(respPayload))
	ts = ts.Add(time.Millisecond)

	// FIN
	writeTCPPacket(t, w, srcMAC, dstMAC, srcIP, dstIP, sp, dp, cSeq, sSeq, false, true, false, true, nil, ts)
	ts = ts.Add(time.Millisecond)

	// FIN-ACK
	writeTCPPacket(t, w, dstMAC, srcMAC, dstIP, srcIP, dp, sp, sSeq, cSeq+1, false, true, false, true, nil, ts)
}
