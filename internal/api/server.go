// Package api implements the AkesoNDR REST API server.
// It exposes endpoints for sensor health, host scores, detections,
// PCAP retrieval, and protocol statistics — all from Section 7.1.
// It also serves the single-page web dashboard.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// DataStore provides access to sensor state for API responses.
type DataStore struct {
	mu sync.RWMutex

	// Sensor health
	Health SensorHealth

	// Host scores
	Hosts []common.HostScore

	// Active detections
	Detections []common.Detection

	// Protocol stats
	ProtocolStats ProtocolStats

	// PCAP files keyed by detection ID
	PcapFiles map[string]string

	// Loaded signature rule count
	SignatureCount  int
	SignatureErrors int
}

// SensorHealth holds live sensor metrics.
type SensorHealth struct {
	Status          string    `json:"status"`
	Uptime          string    `json:"uptime"`
	StartTime       time.Time `json:"start_time"`
	PacketsCaptured uint64    `json:"packets_captured"`
	PacketsDropped  uint64    `json:"packets_dropped"`
	BytesCaptured   uint64    `json:"bytes_captured"`
	PPS             float64   `json:"pps"`
	BPS             float64   `json:"bps"`
	ActiveSessions  int       `json:"active_sessions"`
	MemoryMB        uint64    `json:"memory_mb"`
	DetectionEngine string    `json:"detection_engine"`
}

// ProtocolStats holds per-protocol session/byte counts.
type ProtocolStats struct {
	DNS      ProtocolCount `json:"dns"`
	HTTP     ProtocolCount `json:"http"`
	TLS      ProtocolCount `json:"tls"`
	SMB      ProtocolCount `json:"smb"`
	Kerberos ProtocolCount `json:"kerberos"`
	SSH      ProtocolCount `json:"ssh"`
	SMTP     ProtocolCount `json:"smtp"`
	RDP      ProtocolCount `json:"rdp"`
	NTLM     ProtocolCount `json:"ntlm"`
	LDAP     ProtocolCount `json:"ldap"`
	DCERPC   ProtocolCount `json:"dcerpc"`
	Unknown  ProtocolCount `json:"unknown"`
}

// ProtocolCount tracks session count and bytes for a protocol.
type ProtocolCount struct {
	Sessions uint64 `json:"sessions"`
	Bytes    uint64 `json:"bytes"`
}

// NewDataStore creates an empty data store.
func NewDataStore() *DataStore {
	return &DataStore{
		PcapFiles: make(map[string]string),
		Health: SensorHealth{
			Status:          "running",
			StartTime:       time.Now(),
			DetectionEngine: "active",
		},
	}
}

// Server is the AkesoNDR REST API + dashboard server.
type Server struct {
	router *chi.Mux
	store  *DataStore
	addr   string
}

// NewServer creates the API server with all routes.
func NewServer(addr string, store *DataStore, dashboardDir string) *Server {
	s := &Server{
		router: chi.NewRouter(),
		store:  store,
		addr:   addr,
	}

	// Middleware.
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.RealIP)
	s.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-API-Key"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// API routes.
	s.router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/hosts", s.handleHosts)
		r.Get("/hosts/{ip}", s.handleHostDetail)
		r.Get("/detections", s.handleDetections)
		r.Get("/detections/{id}", s.handleDetectionDetail)
		r.Get("/pcap/{id}", s.handlePcapDownload)
		r.Get("/protocols", s.handleProtocols)
		r.Get("/signatures", s.handleSignatures)
		r.Post("/signatures/reload", s.handleSignaturesReload)
	})

	// Dashboard — serve static files from web/ directory.
	if dashboardDir != "" {
		fs := http.FileServer(http.Dir(dashboardDir))
		s.router.Handle("/*", fs)
	}

	return s
}

// Start begins listening. Blocks until the server is stopped.
func (s *Server) Start() error {
	log.Printf("[api] REST API listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.router)
}

// Router returns the chi.Mux for testing.
func (s *Server) Router() http.Handler {
	return s.router
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	health := s.store.Health
	health.Uptime = time.Since(health.StartTime).Truncate(time.Second).String()
	s.store.mu.RUnlock()
	writeJSON(w, health)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	hosts := s.store.Hosts
	s.store.mu.RUnlock()
	if hosts == nil {
		hosts = []common.HostScore{}
	}
	writeJSON(w, map[string]any{
		"hosts": hosts,
		"total": len(hosts),
	})
}

func (s *Server) handleHostDetail(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()

	for _, h := range s.store.Hosts {
		if h.IP == ip {
			// Find detections for this host.
			var hostDets []common.Detection
			for _, d := range s.store.Detections {
				if d.SrcIP == ip || d.DstIP == ip {
					hostDets = append(hostDets, d)
				}
			}
			writeJSON(w, map[string]any{
				"host":       h,
				"detections": hostDets,
			})
			return
		}
	}
	http.Error(w, `{"error":"host not found"}`, http.StatusNotFound)
}

func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	dets := s.store.Detections
	s.store.mu.RUnlock()
	if dets == nil {
		dets = []common.Detection{}
	}

	// Filter by query params.
	q := r.URL.Query()
	if severity := q.Get("severity"); severity != "" {
		var filtered []common.Detection
		for _, d := range dets {
			if string(rune('0'+d.Severity)) == severity {
				filtered = append(filtered, d)
			}
		}
		dets = filtered
	}
	if typ := q.Get("type"); typ != "" {
		var filtered []common.Detection
		for _, d := range dets {
			if string(d.Type) == typ {
				filtered = append(filtered, d)
			}
		}
		dets = filtered
	}
	if host := q.Get("host"); host != "" {
		var filtered []common.Detection
		for _, d := range dets {
			if d.SrcIP == host || d.DstIP == host {
				filtered = append(filtered, d)
			}
		}
		dets = filtered
	}

	writeJSON(w, map[string]any{
		"detections": dets,
		"total":      len(dets),
	})
}

func (s *Server) handleDetectionDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()

	for _, d := range s.store.Detections {
		if d.ID == id {
			writeJSON(w, d)
			return
		}
	}
	http.Error(w, `{"error":"detection not found"}`, http.StatusNotFound)
}

func (s *Server) handlePcapDownload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.store.mu.RLock()
	path, ok := s.store.PcapFiles[id]
	s.store.mu.RUnlock()

	if !ok {
		http.Error(w, `{"error":"pcap not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".pcap\"")
	http.ServeFile(w, r, path)
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	stats := s.store.ProtocolStats
	s.store.mu.RUnlock()
	writeJSON(w, stats)
}

func (s *Server) handleSignatures(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	writeJSON(w, map[string]any{
		"loaded": s.store.SignatureCount,
		"errors": s.store.SignatureErrors,
	})
}

func (s *Server) handleSignaturesReload(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"status": "reload_triggered",
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] JSON encode error: %v", err)
	}
}
