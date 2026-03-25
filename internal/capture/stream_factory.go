package capture

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

// StreamHandler is the callback interface for completed bidirectional TCP
// streams. Implementations (e.g. the protocol router) receive the
// reassembled data from both directions once the stream is closed.
type StreamHandler interface {
	// HandleStream is called when a bidirectional TCP stream has data.
	// netFlow identifies the network-layer endpoints (IPs),
	// tcpFlow identifies the transport-layer endpoints (ports).
	// client is data sent by the connection initiator (SYN sender),
	// server is data sent by the responder.
	HandleStream(net, transport gopacket.Flow, client, server []byte)
}

// ---------------------------------------------------------------------------
// Stream — one direction of a TCP connection
// ---------------------------------------------------------------------------

// stream accumulates reassembled bytes for one direction of a TCP session.
type stream struct {
	data []byte
	done bool
	bidi *bidiStream
}

func (s *stream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		if r.Skip > 0 {
			continue // gap in stream — skip
		}
		s.data = append(s.data, r.Bytes...)
	}
}

func (s *stream) ReassemblyComplete() {
	s.done = true
	s.bidi.maybeDispatch()
}

// ---------------------------------------------------------------------------
// bidiStream — tracks both directions of a TCP connection
// ---------------------------------------------------------------------------

// bidiStream pairs the two unidirectional streams for a single TCP session.
type bidiStream struct {
	mu        sync.Mutex
	net       gopacket.Flow
	transport gopacket.Flow
	client    *stream // connection initiator
	server    *stream // connection responder
	handler   StreamHandler
	factory   *StreamFactory
	key       string
}

func (b *bidiStream) maybeDispatch() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil || b.server == nil {
		return
	}
	if !b.client.done || !b.server.done {
		return
	}

	// Both directions finished — dispatch to handler.
	if b.handler != nil && (len(b.client.data) > 0 || len(b.server.data) > 0) {
		b.handler.HandleStream(b.net, b.transport, b.client.data, b.server.data)
	}

	// Clean up from factory map.
	b.factory.removeBidi(b.key)
}

// ---------------------------------------------------------------------------
// StreamFactory — creates and tracks bidirectional streams
// ---------------------------------------------------------------------------

// StreamFactory implements gopacket/tcpassembly.StreamFactory. It pairs
// each TCP half-stream with its reverse to form a bidirectional stream,
// then dispatches completed streams to the registered StreamHandler.
type StreamFactory struct {
	handler StreamHandler

	mu    sync.Mutex
	bidis map[string]*bidiStream
}

// NewStreamFactory creates a StreamFactory that dispatches completed
// bidirectional streams to the given handler.
func NewStreamFactory(handler StreamHandler) *StreamFactory {
	return &StreamFactory{
		handler: handler,
		bidis:   make(map[string]*bidiStream),
	}
}

// New implements tcpassembly.StreamFactory.
func (f *StreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	// Build canonical key: sorted so both directions map to the same bidi.
	fwdKey := netFlow.String() + ":" + tcpFlow.String()
	revKey := netFlow.Reverse().String() + ":" + tcpFlow.Reverse().String()

	f.mu.Lock()
	defer f.mu.Unlock()

	s := &stream{}

	// Check if the reverse direction already exists.
	if bidi, ok := f.bidis[revKey]; ok {
		// This is the server (responder) side.
		s.bidi = bidi
		bidi.mu.Lock()
		bidi.server = s
		bidi.mu.Unlock()
		return s
	}

	// First direction seen — create new bidi (this is the client/initiator).
	bidi := &bidiStream{
		net:       netFlow,
		transport: tcpFlow,
		client:    s,
		handler:   f.handler,
		factory:   f,
		key:       fwdKey,
	}
	s.bidi = bidi
	f.bidis[fwdKey] = bidi

	return s
}

func (f *StreamFactory) removeBidi(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.bidis, key)
}

// ActiveStreams returns the number of in-progress bidirectional streams.
func (f *StreamFactory) ActiveStreams() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bidis)
}
