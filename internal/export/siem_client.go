// Package export implements the AkesoNDR SIEM exporter. It batches
// ECS-normalized events and ships them to AkesoSIEM via HTTP POST
// as newline-delimited JSON (NDJSON).
package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// SIEMClient batches and ships ECS events to AkesoSIEM.
type SIEMClient struct {
	cfg    config.ExportConfig
	client *http.Client

	mu    sync.Mutex
	batch []common.ECSEvent

	done chan struct{}
	wg   sync.WaitGroup

	// Stats
	totalSent    uint64
	totalErrors  uint64
	totalBatches uint64
}

// NewSIEMClient creates a SIEM exporter with the given config.
func NewSIEMClient(cfg config.ExportConfig) *SIEMClient {
	return &SIEMClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		batch: make([]common.ECSEvent, 0, cfg.BatchSize),
		done:  make(chan struct{}),
	}
}

// Enqueue adds an ECS event to the batch. If the batch reaches BatchSize,
// it is flushed immediately. Otherwise, it waits for the flush interval.
func (s *SIEMClient) Enqueue(event common.ECSEvent) {
	s.mu.Lock()
	s.batch = append(s.batch, event)
	shouldFlush := len(s.batch) >= s.cfg.BatchSize
	s.mu.Unlock()

	if shouldFlush {
		s.Flush()
	}
}

// Flush sends all queued events to AkesoSIEM immediately.
func (s *SIEMClient) Flush() {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return
	}
	events := s.batch
	s.batch = make([]common.ECSEvent, 0, s.cfg.BatchSize)
	s.mu.Unlock()

	if err := s.sendBatch(events); err != nil {
		atomic.AddUint64(&s.totalErrors, 1)
		log.Printf("[export] Failed to send %d events: %v", len(events), err)
		return
	}

	atomic.AddUint64(&s.totalSent, uint64(len(events)))
	atomic.AddUint64(&s.totalBatches, 1)
}

// Start begins the periodic flush goroutine.
func (s *SIEMClient) Start() {
	if s.cfg.SIEMEndpoint == "" {
		log.Println("[export] No SIEM endpoint configured — events will be discarded")
		return
	}

	interval := s.cfg.FlushInterval.Duration()
	if interval <= 0 {
		interval = 5 * time.Second
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.done:
				s.Flush() // Final flush on shutdown.
				return
			case <-ticker.C:
				s.Flush()
			}
		}
	}()

	log.Printf("[export] SIEM exporter started (endpoint=%s, batch=%d, interval=%s)",
		s.cfg.SIEMEndpoint, s.cfg.BatchSize, interval)
}

// Stop shuts down the exporter, flushing remaining events.
func (s *SIEMClient) Stop() {
	close(s.done)
	s.wg.Wait()
}

// Stats returns export statistics.
func (s *SIEMClient) Stats() (sent, errors, batches uint64) {
	return atomic.LoadUint64(&s.totalSent),
		atomic.LoadUint64(&s.totalErrors),
		atomic.LoadUint64(&s.totalBatches)
}

// QueueSize returns the current number of queued events.
func (s *SIEMClient) QueueSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batch)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (s *SIEMClient) sendBatch(events []common.ECSEvent) error {
	// Encode as NDJSON (newline-delimited JSON).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Retry with exponential backoff.
	var lastErr error
	maxRetries := s.cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			time.Sleep(backoff)
		}

		err := s.doPost(buf.Bytes())
		if err == nil {
			return nil
		}
		lastErr = err

		// Don't retry on auth errors.
		if isAuthError(err) {
			return err
		}
	}

	return fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}

func (s *SIEMClient) doPost(body []byte) error {
	req, err := http.NewRequest("POST", s.cfg.SIEMEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", s.cfg.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return &authError{code: resp.StatusCode}
	case resp.StatusCode == 503:
		return fmt.Errorf("SIEM unavailable (503)")
	default:
		return fmt.Errorf("SIEM returned %d", resp.StatusCode)
	}
}

type authError struct {
	code int
}

func (e *authError) Error() string {
	return fmt.Sprintf("authentication failed (HTTP %d)", e.code)
}

func isAuthError(err error) bool {
	_, ok := err.(*authError)
	return ok
}
