// Package sessions implements the AkesoNDR connection tracker. It maintains
// a 5-tuple state table of active network sessions, tracks TCP session
// lifecycle (SYN → established → FIN/RST → closed) using the Zeek conn_state
// model, and computes per-session metrics (duration, bytes, packets).
package sessions

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
)

// SessionCallback is called when a session is closed or expired.
type SessionCallback func(session *common.SessionMeta)

// session is the internal mutable state for a tracked connection.
type session struct {
	mu   sync.Mutex
	meta common.SessionMeta

	flags    tcpFlags
	lastSeen time.Time
	closed   bool
}

// Tracker maintains the 5-tuple state table and computes session metadata.
type Tracker struct {
	mu       sync.RWMutex
	sessions map[string]*session // key = canonical 5-tuple string

	cfg      config.SessionsConfig
	callback SessionCallback
	done     chan struct{}
	wg       sync.WaitGroup

	// Stats
	totalCreated uint64
	totalClosed  uint64
}

// NewTracker creates a connection tracker with the given config and callback.
func NewTracker(cfg config.SessionsConfig, callback SessionCallback) *Tracker {
	return &Tracker{
		sessions: make(map[string]*session),
		cfg:      cfg,
		callback: callback,
		done:     make(chan struct{}),
	}
}

// TrackPacket processes a single packet and updates session state.
// This is the main entry point — call it for every captured packet.
func (t *Tracker) TrackPacket(pkt gopacket.Packet) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
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
		return
	}

	var srcPort, dstPort uint16
	var isTCP bool
	var tcp *layers.TCP

	if tl := pkt.TransportLayer(); tl != nil {
		switch tp := tl.(type) {
		case *layers.TCP:
			srcPort = uint16(tp.SrcPort)
			dstPort = uint16(tp.DstPort)
			isTCP = true
			tcp = tp
		case *layers.UDP:
			srcPort = uint16(tp.SrcPort)
			dstPort = uint16(tp.DstPort)
		}
	}

	ci := pkt.Metadata().CaptureInfo
	ts := ci.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	payloadLen := len(pkt.TransportLayer().LayerPayload())

	// Build canonical flow key — always store with lower IP:port first
	// so both directions map to the same session.
	flow, isOrig := canonicalFlow(srcIP, dstIP, srcPort, dstPort, proto)
	key := flowKey(flow)

	t.mu.RLock()
	sess, exists := t.sessions[key]
	t.mu.RUnlock()

	if !exists {
		sess = t.createSession(key, flow, srcIP, dstIP, srcPort, dstPort, proto, ts, pkt)
		isOrig = true // creator is always the originator
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.closed {
		return
	}

	sess.lastSeen = ts

	// Update metrics.
	if isOrig {
		sess.meta.OrigPackets++
		sess.meta.OrigBytes += uint64(payloadLen)
	} else {
		sess.meta.RespPackets++
		sess.meta.RespBytes += uint64(payloadLen)
	}

	// Update TCP flags.
	if isTCP && tcp != nil {
		if tcp.SYN && !tcp.ACK {
			sess.flags.origSYN = true
		}
		if tcp.SYN && tcp.ACK {
			sess.flags.respSYN = true
		}
		if tcp.FIN {
			if isOrig {
				sess.flags.origFIN = true
			} else {
				sess.flags.respFIN = true
			}
		}
		if tcp.RST {
			if isOrig {
				sess.flags.origRST = true
			} else {
				sess.flags.respRST = true
			}
		}
		if payloadLen > 0 {
			if isOrig {
				sess.flags.origData = true
			} else {
				sess.flags.respData = true
			}
		}

		sess.meta.ConnState = connState(&sess.flags)

		// Check for session close (FIN+FIN or RST).
		if sess.meta.ConnState == common.ConnStateSF ||
			sess.meta.ConnState == common.ConnStateRSTO ||
			sess.meta.ConnState == common.ConnStateRSTR ||
			sess.meta.ConnState == common.ConnStateREJ {
			t.closeSession(sess, key, ts)
		}
	}
}

// StartCleanup launches a background goroutine that periodically sweeps
// for stale sessions that have exceeded their timeout.
func (t *Tracker) StartCleanup() {
	interval := t.cfg.CleanupInterval.Duration()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-t.done:
				return
			case now := <-ticker.C:
				t.sweepStale(now)
			}
		}
	}()
}

// Stop shuts down the cleanup goroutine and closes all remaining sessions.
func (t *Tracker) Stop() {
	close(t.done)
	t.wg.Wait()

	// Close all remaining sessions.
	now := time.Now()
	t.mu.Lock()
	for key, sess := range t.sessions {
		sess.mu.Lock()
		if !sess.closed {
			t.finalizeSession(sess, now)
			sess.closed = true
		}
		sess.mu.Unlock()
		delete(t.sessions, key)
	}
	t.mu.Unlock()
}

// ActiveSessions returns the current number of tracked sessions.
func (t *Tracker) ActiveSessions() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Stats returns total created and closed session counts.
func (t *Tracker) Stats() (created, closed uint64) {
	return atomic.LoadUint64(&t.totalCreated), atomic.LoadUint64(&t.totalClosed)
}

// GetSession returns a copy of the session metadata for a given flow key.
func (t *Tracker) GetSession(key string) (common.SessionMeta, bool) {
	t.mu.RLock()
	sess, ok := t.sessions[key]
	t.mu.RUnlock()
	if !ok {
		return common.SessionMeta{}, false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.meta, true
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (t *Tracker) createSession(key string, flow common.FlowKey,
	srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8,
	ts time.Time, pkt gopacket.Packet,
) *session {
	transport := common.TransportTCP
	if proto == 17 {
		transport = common.TransportUDP
	} else if proto == 1 {
		transport = common.TransportICMP
	}

	sess := &session{
		meta: common.SessionMeta{
			ID:          fmt.Sprintf("%s-%d", key, ts.UnixNano()),
			CommunityID: CommunityIDFromFlow(srcIP, dstIP, srcPort, dstPort, proto),
			Flow:        flow,
			Transport:   transport,
			StartTime:   ts,
			ConnState:   common.ConnStateS0,
		},
		lastSeen: ts,
	}

	// Extract MACs if available.
	if el := pkt.LinkLayer(); el != nil {
		if eth, ok := el.(*layers.Ethernet); ok {
			sess.meta.SrcMAC = eth.SrcMAC.String()
			sess.meta.DstMAC = eth.DstMAC.String()
		}
	}

	t.mu.Lock()
	t.sessions[key] = sess
	t.mu.Unlock()

	atomic.AddUint64(&t.totalCreated, 1)
	return sess
}

func (t *Tracker) closeSession(sess *session, key string, ts time.Time) {
	t.finalizeSession(sess, ts)
	sess.closed = true

	// Remove from table (in a goroutine to avoid holding sess.mu + t.mu).
	go func() {
		t.mu.Lock()
		delete(t.sessions, key)
		t.mu.Unlock()
	}()
}

func (t *Tracker) finalizeSession(sess *session, ts time.Time) {
	sess.meta.EndTime = ts
	sess.meta.Duration = ts.Sub(sess.meta.StartTime)
	atomic.AddUint64(&t.totalClosed, 1)

	if t.callback != nil {
		meta := sess.meta // copy
		t.callback(&meta)
	}
}

func (t *Tracker) sweepStale(now time.Time) {
	tcpTimeout := t.cfg.TCPTimeout.Duration()
	udpTimeout := t.cfg.UDPTimeout.Duration()
	if tcpTimeout <= 0 {
		tcpTimeout = 5 * time.Minute
	}
	if udpTimeout <= 0 {
		udpTimeout = 2 * time.Minute
	}

	var stale []string

	t.mu.RLock()
	for key, sess := range t.sessions {
		sess.mu.Lock()
		if sess.closed {
			sess.mu.Unlock()
			continue
		}
		timeout := tcpTimeout
		if sess.meta.Transport == common.TransportUDP {
			timeout = udpTimeout
		}
		if now.Sub(sess.lastSeen) > timeout {
			stale = append(stale, key)
		}
		sess.mu.Unlock()
	}
	t.mu.RUnlock()

	if len(stale) == 0 {
		return
	}

	t.mu.Lock()
	for _, key := range stale {
		if sess, ok := t.sessions[key]; ok {
			sess.mu.Lock()
			if !sess.closed {
				t.finalizeSession(sess, now)
				sess.closed = true
			}
			sess.mu.Unlock()
			delete(t.sessions, key)
		}
	}
	t.mu.Unlock()

	log.Printf("[sessions] Swept %d stale sessions (active=%d)", len(stale), t.ActiveSessions())
}

// ---------------------------------------------------------------------------
// Flow key helpers
// ---------------------------------------------------------------------------

// canonicalFlow builds a FlowKey with the lower IP:port as source,
// so both directions of a session map to the same key. Returns isOrig=true
// if the provided srcIP:srcPort is the canonical source (originator).
func canonicalFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) (common.FlowKey, bool) {
	srcStr := srcIP.String()
	dstStr := dstIP.String()

	isOrig := true
	if srcStr > dstStr || (srcStr == dstStr && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
		isOrig = false
	}

	return common.FlowKey{
		SrcIP:    append(net.IP(nil), srcIP...),
		DstIP:    append(net.IP(nil), dstIP...),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: proto,
	}, isOrig
}

func flowKey(f common.FlowKey) string {
	return fmt.Sprintf("%s:%d-%s:%d/%d", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
}
