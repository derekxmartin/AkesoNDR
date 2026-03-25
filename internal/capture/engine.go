// Package capture implements the AkesoNDR packet capture engine using
// gopacket/pcap for live interface capture and gopacket/pcapgo for
// offline PCAP file replay.
package capture

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/akesondr/akeso-ndr/internal/config"

	"os"
)

// Packet wraps a gopacket.Packet with capture-time metadata.
type Packet struct {
	Data      gopacket.Packet
	Timestamp time.Time
	Length    int // Original wire length
}

// Metrics holds live capture statistics, safe for concurrent reads.
type Metrics struct {
	PacketsReceived uint64
	PacketsDropped  uint64
	BytesReceived   uint64
	StartTime       time.Time
}

// PPS returns the average packets-per-second since capture start.
func (m *Metrics) PPS() float64 {
	elapsed := time.Since(m.StartTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadUint64(&m.PacketsReceived)) / elapsed
}

// BPS returns the average bytes-per-second since capture start.
func (m *Metrics) BPS() float64 {
	elapsed := time.Since(m.StartTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadUint64(&m.BytesReceived)) / elapsed
}

// Engine is the packet capture engine. It reads packets from either a live
// interface (via libpcap) or a PCAP file and sends them on the Packets channel.
type Engine struct {
	cfg     config.CaptureConfig
	packets chan Packet
	metrics Metrics
	done    chan struct{}
	wg      sync.WaitGroup

	// For offline mode
	pcapFile string
}

// NewEngine creates a capture engine from the given config.
// Set pcapFile to a non-empty path for offline PCAP replay mode.
func NewEngine(cfg config.CaptureConfig, pcapFile string, packetBufSize int) *Engine {
	if packetBufSize <= 0 {
		packetBufSize = 1000
	}
	return &Engine{
		cfg:      cfg,
		pcapFile: pcapFile,
		packets:  make(chan Packet, packetBufSize),
		done:     make(chan struct{}),
	}
}

// Packets returns the read-only channel of captured packets.
func (e *Engine) Packets() <-chan Packet {
	return e.packets
}

// GetMetrics returns a snapshot of capture metrics.
func (e *Engine) GetMetrics() Metrics {
	return Metrics{
		PacketsReceived: atomic.LoadUint64(&e.metrics.PacketsReceived),
		PacketsDropped:  atomic.LoadUint64(&e.metrics.PacketsDropped),
		BytesReceived:   atomic.LoadUint64(&e.metrics.BytesReceived),
		StartTime:       e.metrics.StartTime,
	}
}

// Start begins packet capture. It returns immediately; packets are delivered
// on the Packets() channel. Call Stop() to shut down.
func (e *Engine) Start() error {
	if e.pcapFile != "" {
		return e.startOffline()
	}
	return e.startLive()
}

// Stop signals the capture goroutine to finish and waits for completion.
// The Packets channel is closed once the goroutine exits.
func (e *Engine) Stop() {
	close(e.done)
	e.wg.Wait()
}

// ---------------------------------------------------------------------------
// Live capture (libpcap)
// ---------------------------------------------------------------------------

func (e *Engine) startLive() error {
	inactive, err := pcap.NewInactiveHandle(e.cfg.Interface)
	if err != nil {
		return fmt.Errorf("capture: open interface %s: %w", e.cfg.Interface, err)
	}

	if err := inactive.SetSnapLen(e.cfg.SnapLen); err != nil {
		inactive.CleanUp()
		return fmt.Errorf("capture: set snap_len: %w", err)
	}
	if err := inactive.SetPromisc(e.cfg.Promisc); err != nil {
		inactive.CleanUp()
		return fmt.Errorf("capture: set promiscuous: %w", err)
	}
	if err := inactive.SetTimeout(pcap.BlockForever); err != nil {
		inactive.CleanUp()
		return fmt.Errorf("capture: set timeout: %w", err)
	}
	if e.cfg.BufferSize > 0 {
		if err := inactive.SetBufferSize(e.cfg.BufferSize * 1024 * 1024); err != nil {
			inactive.CleanUp()
			return fmt.Errorf("capture: set buffer_size: %w", err)
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		inactive.CleanUp()
		return fmt.Errorf("capture: activate %s: %w", e.cfg.Interface, err)
	}

	if e.cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(e.cfg.BPFFilter); err != nil {
			handle.Close()
			return fmt.Errorf("capture: set BPF filter %q: %w", e.cfg.BPFFilter, err)
		}
		log.Printf("[capture] BPF filter applied: %s", e.cfg.BPFFilter)
	}

	log.Printf("[capture] Live capture on %s (snap_len=%d, promisc=%v)",
		e.cfg.Interface, e.cfg.SnapLen, e.cfg.Promisc)

	e.metrics.StartTime = time.Now()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions.Lazy = true
	source.DecodeOptions.NoCopy = true

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer handle.Close()
		defer close(e.packets)
		e.readPackets(source)
		// Log final pcap stats if available.
		if stats, err := handle.Stats(); err == nil {
			atomic.StoreUint64(&e.metrics.PacketsDropped, uint64(stats.PacketsDropped))
			log.Printf("[capture] Final stats: received=%d dropped=%d",
				stats.PacketsReceived, stats.PacketsDropped)
		}
	}()

	// Periodically poll pcap stats for drops.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.done:
				return
			case <-ticker.C:
				m := e.GetMetrics()
				log.Printf("[capture] pps=%.0f bps=%.0f packets=%d bytes=%d",
					m.PPS(), m.BPS(), m.PacketsReceived, m.BytesReceived)
				if stats, err := handle.Stats(); err == nil {
					atomic.StoreUint64(&e.metrics.PacketsDropped, uint64(stats.PacketsDropped))
				}
			}
		}
	}()

	return nil
}

// ---------------------------------------------------------------------------
// Offline PCAP replay (pcapgo)
// ---------------------------------------------------------------------------

func (e *Engine) startOffline() error {
	f, err := os.Open(e.pcapFile)
	if err != nil {
		return fmt.Errorf("capture: open pcap %s: %w", e.pcapFile, err)
	}

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("capture: read pcap %s: %w", e.pcapFile, err)
	}

	log.Printf("[capture] Offline replay from %s", e.pcapFile)
	e.metrics.StartTime = time.Now()

	source := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
	source.DecodeOptions.Lazy = true
	source.DecodeOptions.NoCopy = true

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer f.Close()
		defer close(e.packets)
		e.readPackets(source)
		m := e.GetMetrics()
		log.Printf("[capture] Replay complete: packets=%d bytes=%d",
			m.PacketsReceived, m.BytesReceived)
	}()

	return nil
}

// ---------------------------------------------------------------------------
// Shared packet loop
// ---------------------------------------------------------------------------

func (e *Engine) readPackets(source *gopacket.PacketSource) {
	for {
		select {
		case <-e.done:
			return
		default:
		}

		pkt, err := source.NextPacket()
		if err != nil {
			// io.EOF or pcap read error — normal for offline mode.
			return
		}

		ci := pkt.Metadata().CaptureInfo
		atomic.AddUint64(&e.metrics.PacketsReceived, 1)
		atomic.AddUint64(&e.metrics.BytesReceived, uint64(ci.Length))

		p := Packet{
			Data:      pkt,
			Timestamp: ci.Timestamp,
			Length:    ci.Length,
		}

		select {
		case e.packets <- p:
		case <-e.done:
			return
		}
	}
}
