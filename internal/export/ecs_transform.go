package export

import (
	"github.com/akesondr/akeso-ndr/internal/common"
)

// TransformSession converts a SessionMeta to an ECS event ready for export.
func TransformSession(s *common.SessionMeta) common.ECSEvent {
	return common.MapSessionToECS(s)
}

// TransformDetection converts a Detection to an ECS alert event.
func TransformDetection(d *common.Detection) common.ECSEvent {
	return common.MapDetectionToECS(d)
}

// TransformHostScore converts a HostScore to an ECS metric event.
func TransformHostScore(h *common.HostScore) common.ECSEvent {
	return common.MapHostScoreToECS(h)
}

// ExportPipeline wraps the SIEM client with transformation helpers.
type ExportPipeline struct {
	client *SIEMClient
}

// NewExportPipeline creates a pipeline that transforms and exports events.
func NewExportPipeline(client *SIEMClient) *ExportPipeline {
	return &ExportPipeline{client: client}
}

// ExportSession transforms and enqueues a session event.
func (p *ExportPipeline) ExportSession(s *common.SessionMeta) {
	event := TransformSession(s)
	p.client.Enqueue(event)
}

// ExportDetection transforms and enqueues a detection alert.
func (p *ExportPipeline) ExportDetection(d *common.Detection) {
	event := TransformDetection(d)
	p.client.Enqueue(event)
}

// ExportHostScore transforms and enqueues a host score metric.
func (p *ExportPipeline) ExportHostScore(h *common.HostScore) {
	event := TransformHostScore(h)
	p.client.Enqueue(event)
}

// Flush forces an immediate send of all queued events.
func (p *ExportPipeline) Flush() {
	p.client.Flush()
}
