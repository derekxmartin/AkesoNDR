package capture

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// Assembler wraps gopacket's tcpassembly.Assembler and provides a simple
// interface for feeding packets from the capture engine and flushing
// timed-out streams.
type Assembler struct {
	asm     *tcpassembly.Assembler
	factory *StreamFactory
	done    chan struct{}
}

// NewAssembler creates a TCP stream assembler that dispatches completed
// bidirectional streams to the given handler.
func NewAssembler(handler StreamHandler) *Assembler {
	factory := NewStreamFactory(handler)
	pool := tcpassembly.NewStreamPool(factory)
	asm := tcpassembly.NewAssembler(pool)

	return &Assembler{
		asm:     asm,
		factory: factory,
		done:    make(chan struct{}),
	}
}

// ProcessPacket extracts the TCP layer from a packet and feeds it to the
// assembler. Non-TCP packets are silently ignored.
func (a *Assembler) ProcessPacket(pkt gopacket.Packet) {
	tcp, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok {
		return
	}
	a.asm.AssembleWithTimestamp(
		pkt.NetworkLayer().NetworkFlow(),
		tcp,
		pkt.Metadata().Timestamp,
	)
}

// StartFlusher launches a background goroutine that periodically flushes
// streams older than maxAge. Call Stop() to terminate.
func (a *Assembler) StartFlusher(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-a.done:
				return
			case <-ticker.C:
				flushed, _ := a.asm.FlushOlderThan(time.Now().Add(-maxAge))
				if flushed > 0 {
					log.Printf("[reassembly] Flushed %d old streams (active=%d)",
						flushed, a.factory.ActiveStreams())
				}
			}
		}
	}()
}

// FlushAll flushes all remaining streams. Call during shutdown.
func (a *Assembler) FlushAll() {
	a.asm.FlushAll()
}

// Stop terminates the flusher goroutine and flushes remaining streams.
func (a *Assembler) Stop() {
	close(a.done)
	a.FlushAll()
}

// ActiveStreams returns the number of in-progress bidirectional streams.
func (a *Assembler) ActiveStreams() int {
	return a.factory.ActiveStreams()
}
