// Package capture — pcap_buffer.go implements a rolling PCAP evidence buffer.
//
// Inspired by Vectra's rolling buffer approach, AkesoNDR retains raw packets
// in a ring buffer on disk. When a detection fires, the relevant packets
// (identified by flow 5-tuple and timestamp range) are extracted into a
// detection-specific PCAP file for analyst investigation.
//
// Design:
//   - Packets are written to segment files (e.g. buffer_000.pcap).
//   - Each segment has a configurable max size (default: 64 MB).
//   - When total disk usage exceeds MaxSizeMB, the oldest segment is evicted.
//   - An in-memory index maps flow keys → packet locations for fast extraction.
//   - Extraction produces a valid PCAP file containing only the matched packets.
package capture

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/akesondr/akeso-ndr/internal/config"
)

const (
	// segmentMaxBytes is the max size per segment file (64 MB).
	segmentMaxBytes = 64 * 1024 * 1024
	// pcapSnapLen is the snap length written into PCAP file headers.
	pcapSnapLen = 65535
)

// packetRef records where a packet lives on disk and what flow it belongs to.
type packetRef struct {
	segmentID int
	flowKey   string
	timestamp time.Time
}

// segment represents a single PCAP segment file on disk.
type segment struct {
	id       int
	path     string
	writer   *pcapgo.Writer
	file     *os.File
	size     int64
	created  time.Time
	closed   bool
}

// PcapBuffer is the rolling PCAP evidence ring buffer.
type PcapBuffer struct {
	mu sync.Mutex

	cfg        config.PcapBufferConfig
	storageDir string

	segments   []*segment
	currentSeg *segment
	nextSegID  int

	// Per-flow packet index: flowKey → list of refs.
	index map[string][]packetRef

	// Per-flow packet count for MaxFlowPackets enforcement.
	flowCounts map[string]int

	totalBytes int64
}

// NewPcapBuffer creates a new ring buffer with the given config.
func NewPcapBuffer(cfg config.PcapBufferConfig) (*PcapBuffer, error) {
	dir := cfg.StoragePath
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "akeso-ndr-pcap")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("pcap_buffer: create dir %s: %w", dir, err)
	}

	buf := &PcapBuffer{
		cfg:        cfg,
		storageDir: dir,
		index:      make(map[string][]packetRef),
		flowCounts: make(map[string]int),
	}

	if err := buf.rotateSegment(); err != nil {
		return nil, err
	}

	log.Printf("[pcap_buffer] Initialized: dir=%s max_size=%dMB max_flow_packets=%d",
		dir, cfg.MaxSizeMB, cfg.MaxFlowPackets)
	return buf, nil
}

// WritePacket stores a raw packet in the ring buffer.
// flowKey is the canonical 5-tuple string (same key the tracker uses).
func (b *PcapBuffer) WritePacket(pkt gopacket.Packet, flowKey string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Enforce per-flow packet cap.
	maxFlow := b.cfg.MaxFlowPackets
	if maxFlow <= 0 {
		maxFlow = 50
	}
	if b.flowCounts[flowKey] >= maxFlow {
		return nil // silently drop — quota exceeded for this flow
	}

	ci := pkt.Metadata().CaptureInfo
	if ci.CaptureLength == 0 {
		ci.CaptureLength = len(pkt.Data())
	}
	if ci.Length == 0 {
		ci.Length = ci.CaptureLength
	}
	if ci.Timestamp.IsZero() {
		ci.Timestamp = time.Now()
	}

	// Rotate segment if current is full.
	if b.currentSeg.size >= segmentMaxBytes {
		if err := b.rotateSegment(); err != nil {
			return err
		}
	}

	// Write packet to current segment.
	if err := b.currentSeg.writer.WritePacket(ci, pkt.Data()); err != nil {
		return fmt.Errorf("pcap_buffer: write packet: %w", err)
	}

	pktSize := int64(ci.CaptureLength + 16) // pcap record header = 16 bytes
	b.currentSeg.size += pktSize
	b.totalBytes += pktSize

	// Index the packet.
	ref := packetRef{
		segmentID: b.currentSeg.id,
		flowKey:   flowKey,
		timestamp: ci.Timestamp,
	}
	b.index[flowKey] = append(b.index[flowKey], ref)
	b.flowCounts[flowKey]++

	// Evict oldest segments if over budget.
	b.evictIfNeeded()

	return nil
}

// ExtractFlow extracts all packets for a given flow key within a time range
// and writes them to a new PCAP file at outPath. Returns the number of
// packets written.
func (b *PcapBuffer) ExtractFlow(flowKey string, start, end time.Time, outPath string) (int, error) {
	b.mu.Lock()
	refs, ok := b.index[flowKey]
	if !ok {
		b.mu.Unlock()
		return 0, fmt.Errorf("pcap_buffer: no packets for flow %s", flowKey)
	}

	// Collect matching refs.
	var matched []packetRef
	for _, r := range refs {
		if !r.timestamp.Before(start) && !r.timestamp.After(end) {
			matched = append(matched, r)
		}
	}
	b.mu.Unlock()

	if len(matched) == 0 {
		return 0, fmt.Errorf("pcap_buffer: no packets in time range for flow %s", flowKey)
	}

	// Group by segment for efficient reading.
	bySegment := make(map[int][]packetRef)
	for _, r := range matched {
		bySegment[r.segmentID] = append(bySegment[r.segmentID], r)
	}

	// Create output PCAP.
	outFile, err := os.Create(outPath)
	if err != nil {
		return 0, fmt.Errorf("pcap_buffer: create output %s: %w", outPath, err)
	}
	defer outFile.Close()

	outWriter := pcapgo.NewWriter(outFile)
	if err := outWriter.WriteFileHeader(pcapSnapLen, layers.LinkTypeEthernet); err != nil {
		return 0, fmt.Errorf("pcap_buffer: write header: %w", err)
	}

	// Read each segment and extract matching packets.
	written := 0
	segIDs := make([]int, 0, len(bySegment))
	for id := range bySegment {
		segIDs = append(segIDs, id)
	}
	sort.Ints(segIDs)

	for _, segID := range segIDs {
		segRefs := bySegment[segID]
		n, err := b.extractFromSegment(segID, segRefs, flowKey, start, end, outWriter)
		if err != nil {
			log.Printf("[pcap_buffer] Warning: segment %d read error: %v", segID, err)
			continue
		}
		written += n
	}

	return written, nil
}

// Stats returns buffer statistics.
func (b *PcapBuffer) Stats() (totalBytes int64, segments int, flows int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.totalBytes, len(b.segments), len(b.index)
}

// Close flushes and closes all segment files.
func (b *PcapBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, seg := range b.segments {
		if !seg.closed {
			seg.file.Close()
			seg.closed = true
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (b *PcapBuffer) rotateSegment() error {
	// Close current segment.
	if b.currentSeg != nil && !b.currentSeg.closed {
		b.currentSeg.file.Close()
		b.currentSeg.closed = true
	}

	// Create new segment file.
	seg, err := b.newSegment()
	if err != nil {
		return err
	}
	b.currentSeg = seg
	b.segments = append(b.segments, seg)
	return nil
}

func (b *PcapBuffer) newSegment() (*segment, error) {
	id := b.nextSegID
	b.nextSegID++

	path := filepath.Join(b.storageDir, fmt.Sprintf("buffer_%06d.pcap", id))
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("pcap_buffer: create segment %s: %w", path, err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(pcapSnapLen, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, fmt.Errorf("pcap_buffer: write header: %w", err)
	}

	headerSize := int64(24) // pcap global header = 24 bytes

	return &segment{
		id:      id,
		path:    path,
		writer:  w,
		file:    f,
		size:    headerSize,
		created: time.Now(),
	}, nil
}

func (b *PcapBuffer) evictIfNeeded() {
	maxBytes := int64(b.cfg.MaxSizeMB) * 1024 * 1024
	if maxBytes <= 0 {
		return
	}

	for b.totalBytes > maxBytes && len(b.segments) > 1 {
		b.evictOldest()
	}
}

func (b *PcapBuffer) evictOldest() {
	oldest := b.segments[0]
	b.segments = b.segments[1:]

	if !oldest.closed {
		oldest.file.Close()
		oldest.closed = true
	}
	os.Remove(oldest.path)

	b.totalBytes -= oldest.size

	// Remove index entries for the evicted segment.
	for flowKey, refs := range b.index {
		var kept []packetRef
		removed := 0
		for _, r := range refs {
			if r.segmentID == oldest.id {
				removed++
			} else {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(b.index, flowKey)
			delete(b.flowCounts, flowKey)
		} else {
			b.index[flowKey] = kept
			b.flowCounts[flowKey] -= removed
		}
	}

	log.Printf("[pcap_buffer] Evicted segment %d (%s, %d bytes)",
		oldest.id, oldest.path, oldest.size)
}

// extractFromSegment reads a segment file and writes matching packets to the
// output writer. It re-reads the full segment and matches packets by flow key
// and timestamp range (since we don't store byte offsets per packet).
func (b *PcapBuffer) extractFromSegment(segID int, refs []packetRef, flowKey string, start, end time.Time, out *pcapgo.Writer) (int, error) {
	// Find the segment path.
	var segPath string
	b.mu.Lock()
	for _, seg := range b.segments {
		if seg.id == segID {
			segPath = seg.path
			break
		}
	}
	b.mu.Unlock()

	if segPath == "" {
		return 0, fmt.Errorf("segment %d not found (evicted?)", segID)
	}

	f, err := os.Open(segPath)
	if err != nil {
		return 0, fmt.Errorf("open segment %s: %w", segPath, err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("read segment %s: %w", segPath, err)
	}

	written := 0
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, fmt.Errorf("read packet: %w", err)
		}

		// Check timestamp in range.
		if ci.Timestamp.Before(start) || ci.Timestamp.After(end) {
			continue
		}

		// Check if this packet belongs to the target flow by decoding
		// the 5-tuple and comparing the flow key.
		pktFlowKey := extractFlowKeyFromData(data)
		if pktFlowKey != flowKey {
			continue
		}

		if err := out.WritePacket(ci, data); err != nil {
			return written, fmt.Errorf("write extracted packet: %w", err)
		}
		written++
	}

	return written, nil
}

// extractFlowKeyFromData does a minimal decode of packet data to extract the
// canonical flow key. This is used during extraction to match packets.
func extractFlowKeyFromData(data []byte) string {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return ""
	}

	var srcIP, dstIP net.IP
	var proto uint8
	switch n := netLayer.(type) {
	case *layers.IPv4:
		srcIP = n.SrcIP
		dstIP = n.DstIP
		proto = uint8(n.Protocol)
	case *layers.IPv6:
		srcIP = n.SrcIP
		dstIP = n.DstIP
		proto = uint8(n.NextHeader)
	default:
		return ""
	}

	var srcPort, dstPort uint16
	if tl := pkt.TransportLayer(); tl != nil {
		switch tp := tl.(type) {
		case *layers.TCP:
			srcPort = uint16(tp.SrcPort)
			dstPort = uint16(tp.DstPort)
		case *layers.UDP:
			srcPort = uint16(tp.SrcPort)
			dstPort = uint16(tp.DstPort)
		}
	}

	// Canonical ordering (same as sessions.canonicalFlow).
	srcStr := srcIP.String()
	dstStr := dstIP.String()
	if srcStr > dstStr || (srcStr == dstStr && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return fmt.Sprintf("%s:%d-%s:%d/%d", srcIP, srcPort, dstIP, dstPort, proto)
}
