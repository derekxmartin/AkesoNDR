package export

import (
	"log"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// HostScoreProvider returns all current host scores.
type HostScoreProvider func() []common.HostScore

// HostScoreExporter periodically exports host score events to the SIEM.
type HostScoreExporter struct {
	pipeline *ExportPipeline
	provider HostScoreProvider
	interval time.Duration

	done chan struct{}
	wg   sync.WaitGroup
}

// NewHostScoreExporter creates a periodic host score exporter.
func NewHostScoreExporter(pipeline *ExportPipeline, provider HostScoreProvider, interval time.Duration) *HostScoreExporter {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &HostScoreExporter{
		pipeline: pipeline,
		provider: provider,
		interval: interval,
		done:     make(chan struct{}),
	}
}

// Start begins periodic host score export.
func (h *HostScoreExporter) Start() {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		for {
			select {
			case <-h.done:
				return
			case <-ticker.C:
				h.exportScores()
			}
		}
	}()
	log.Printf("[export] Host score exporter started (interval=%s)", h.interval)
}

// Stop shuts down the exporter.
func (h *HostScoreExporter) Stop() {
	close(h.done)
	h.wg.Wait()
}

// ExportNow forces an immediate export of all host scores.
func (h *HostScoreExporter) ExportNow() {
	h.exportScores()
}

func (h *HostScoreExporter) exportScores() {
	scores := h.provider()
	if len(scores) == 0 {
		return
	}

	for i := range scores {
		h.pipeline.ExportHostScore(&scores[i])
	}

	log.Printf("[export] Exported %d host scores", len(scores))
}
