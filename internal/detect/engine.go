// Package detect implements the AkesoNDR behavioral detection engine.
//
// The engine provides a framework for registering detectors, feeding them
// network events (sessions, protocol metadata), and collecting alerts.
// Each detector implements the Detector interface and is registered by type.
// The engine fans out events to all registered detectors and collects
// Detection alerts through a callback pipeline.
package detect

import (
	"log"
	"sync"
	"time"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// Detector is the interface all behavioral detectors must implement.
type Detector interface {
	// Name returns the detector's human-readable name.
	Name() string

	// Type returns the detection type this detector produces.
	Type() common.DetectionType

	// ProcessSession is called for every closed/expired session.
	ProcessSession(session *common.SessionMeta)

	// ProcessProtocol is called for protocol-specific metadata.
	ProcessProtocol(meta any, protocol string)

	// Check runs periodic analysis and returns any new detections.
	// Called on a timer by the engine.
	Check() []*common.Detection
}

// AlertCallback is called when the engine produces a detection alert.
type AlertCallback func(detection *common.Detection)

// Engine is the behavioral detection engine. It manages detector
// registration, event distribution, and periodic checking.
type Engine struct {
	mu        sync.RWMutex
	detectors []Detector
	callback  AlertCallback
	done      chan struct{}
	wg        sync.WaitGroup

	// Stats
	totalAlerts uint64
	alertsByType map[common.DetectionType]uint64
}

// NewEngine creates a detection engine with the given alert callback.
func NewEngine(callback AlertCallback) *Engine {
	return &Engine{
		callback:     callback,
		done:         make(chan struct{}),
		alertsByType: make(map[common.DetectionType]uint64),
	}
}

// Register adds a detector to the engine.
func (e *Engine) Register(d Detector) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detectors = append(e.detectors, d)
	log.Printf("[detect] Registered detector: %s (%s)", d.Name(), d.Type())
}

// ProcessSession distributes a closed session to all detectors.
func (e *Engine) ProcessSession(session *common.SessionMeta) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, d := range e.detectors {
		d.ProcessSession(session)
	}
}

// ProcessProtocol distributes protocol metadata to all detectors.
func (e *Engine) ProcessProtocol(meta any, protocol string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, d := range e.detectors {
		d.ProcessProtocol(meta, protocol)
	}
}

// Start begins the periodic check loop. Detectors are polled at the
// given interval and any resulting alerts are dispatched.
func (e *Engine) Start(checkInterval time.Duration) {
	if checkInterval <= 0 {
		checkInterval = 10 * time.Second
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-e.done:
				// Final check before shutdown.
				e.runChecks()
				return
			case <-ticker.C:
				e.runChecks()
			}
		}
	}()

	log.Printf("[detect] Engine started (check_interval=%s, detectors=%d)",
		checkInterval, len(e.detectors))
}

// Stop shuts down the detection engine and runs a final check.
func (e *Engine) Stop() {
	close(e.done)
	e.wg.Wait()
}

// Stats returns detection counts by type.
func (e *Engine) Stats() (total uint64, byType map[common.DetectionType]uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := make(map[common.DetectionType]uint64, len(e.alertsByType))
	for k, v := range e.alertsByType {
		cp[k] = v
	}
	return e.totalAlerts, cp
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (e *Engine) runChecks() {
	e.mu.RLock()
	detectors := make([]Detector, len(e.detectors))
	copy(detectors, e.detectors)
	e.mu.RUnlock()

	for _, d := range detectors {
		alerts := d.Check()
		for _, alert := range alerts {
			e.emit(alert)
		}
	}
}

func (e *Engine) emit(alert *common.Detection) {
	e.mu.Lock()
	e.totalAlerts++
	e.alertsByType[alert.Type]++
	e.mu.Unlock()

	log.Printf("[detect] ALERT: %s severity=%d certainty=%d src=%s dst=%s mitre=%s/%s",
		alert.Name, alert.Severity, alert.Certainty,
		alert.SrcIP, alert.DstIP,
		alert.MITRE.TacticName, alert.MITRE.TechniqueName)

	if e.callback != nil {
		e.callback(alert)
	}
}
