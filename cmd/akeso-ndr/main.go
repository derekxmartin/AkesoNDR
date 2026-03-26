package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"

	"github.com/akesondr/akeso-ndr/internal/api"
	"github.com/akesondr/akeso-ndr/internal/capture"
	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
	"github.com/akesondr/akeso-ndr/internal/detect"
	"github.com/akesondr/akeso-ndr/internal/protocols"
	"github.com/akesondr/akeso-ndr/internal/sessions"

	// Blank imports to verify all packages compile.
	_ "github.com/akesondr/akeso-ndr/internal/export"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dcerpc"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/kerberos"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ldap"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ntlm"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/rdp"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/smb"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/smtp"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ssh"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/tls"
	_ "github.com/akesondr/akeso-ndr/internal/signatures"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	iface := flag.String("interface", "", "Network interface to capture on (e.g. eth0)")
	pcapFile := flag.String("pcap", "", "Path to PCAP file for offline replay")
	configPath := flag.String("config", "", "Path to akeso-ndr.toml config file")
	apiAddr := flag.String("api", ":8080", "REST API listen address")
	dashDir := flag.String("dashboard", "web/dashboard", "Path to dashboard static files")
	demo := flag.Bool("demo", false, "Seed dashboard with sample data for demonstration")
	flag.Parse()

	fmt.Println("AkesoNDR — Network Detection & Response")
	fmt.Printf("Version: %s\n", version)

	// Load config (optional — fall back to defaults + flags).
	cfg := config.DefaultConfig()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("[sensor] Config error: %v", err)
		}
		cfg = loaded
		log.Printf("[sensor] Config loaded from %s", *configPath)
	}

	// CLI flags override config file values.
	if *iface != "" {
		cfg.Capture.Interface = *iface
	}
	if *apiAddr != "" {
		cfg.API.ListenAddr = *apiAddr
	}

	// --- Shared data store for API ---
	store := api.NewDataStore()
	store.Health.StartTime = time.Now()

	// Seed with demo data if requested.
	if *demo {
		seedDemoData(store)
		log.Println("[sensor] Demo mode — dashboard seeded with sample data")
	}

	// --- Detection engine ---
	var detMu sync.Mutex
	detectionEngine := detect.NewEngine(func(d *common.Detection) {
		log.Printf("[detection] %s | severity=%d certainty=%d | %s → %s | %s %s",
			d.Name, d.Severity, d.Certainty, d.SrcIP, d.DstIP,
			d.MITRE.TechniqueID, d.MITRE.TacticName)

		detMu.Lock()
		store.Detections = append(store.Detections, *d)
		detMu.Unlock()

		// Update host scores.
		store.Mu.Lock()
		store.Hosts = buildHostScores(store.Detections)
		store.Mu.Unlock()
	})
	detectionEngine.Start(10 * time.Second)

	// --- Protocol router: logs metadata + feeds detection engine ---
	router := protocols.NewRouter(func(meta any, protocol string, net, transport gopacket.Flow) {
		switch protocol {
		case "dns":
			if dm, ok := meta.(*common.DNSMeta); ok {
				if dm.TotalAnswers > 0 {
					log.Printf("[dns] %s → %s | %s %s → %s (answers=%d, rcode=%s)",
						net.Src(), net.Dst(), dm.Proto, dm.Query, dm.Answers[0].Data,
						dm.TotalAnswers, dm.RCodeName)
				} else {
					log.Printf("[dns] %s → %s | %s %s %s (entropy=%.2f, depth=%d)",
						net.Src(), net.Dst(), dm.Proto, dm.QTypeName, dm.Query,
						dm.Entropy, dm.SubdomainDepth)
				}
				// Feed to DNS tunnel detector.
				detectionEngine.ProcessProtocol(dm, "dns")
			}
		case "http":
			if hm, ok := meta.(*common.HTTPMeta); ok {
				log.Printf("[http] %s → %s | %s %s → %d %s (req=%d resp=%d bytes, ua=%s)",
					net.Src(), net.Dst(), hm.Method, hm.Host+hm.URI,
					hm.StatusCode, hm.StatusMsg,
					hm.RequestBodyLen, hm.ResponseBodyLen,
					hm.UserAgent)
			}
		case "tls":
			if tm, ok := meta.(*common.TLSMeta); ok && tm != nil {
				log.Printf("[tls] %s → %s | %s sni=%s cipher=%s ja3=%s",
					net.Src(), net.Dst(), tm.Version, tm.ServerName, tm.Cipher, tm.JA3)
			} else {
				log.Printf("[tls] %s → %s | TLS session detected", net.Src(), net.Dst())
			}
		case "smb":
			if sm, ok := meta.(*common.SMBMeta); ok {
				log.Printf("[smb] %s → %s | %s action=%s path=%s user=%s",
					net.Src(), net.Dst(), sm.Version, sm.Action, sm.Path, sm.Username)
			}
		case "kerberos":
			if km, ok := meta.(*common.KerberosMeta); ok {
				if km.Success {
					log.Printf("[kerberos] %s → %s | %s client=%s service=%s cipher=%d",
						net.Src(), net.Dst(), km.RequestType, km.Client, km.Service, km.RepCipher)
				} else {
					log.Printf("[kerberos] %s → %s | %s client=%s error=%s",
						net.Src(), net.Dst(), km.RequestType, km.Client, km.ErrorMsg)
				}
				// Feed to Kerberos attack detector.
				detectionEngine.ProcessProtocol(km, "kerberos")
			}
		case "ssh":
			if sm, ok := meta.(*common.SSHMeta); ok {
				log.Printf("[ssh] %s → %s | v%d client=%s server=%s hassh=%s",
					net.Src(), net.Dst(), sm.Version, sm.Client, sm.Server, sm.HASSH)
			}
		case "smtp":
			if sm, ok := meta.(*common.SMTPMeta); ok {
				log.Printf("[smtp] %s → %s | from=%s to=%v subject=%s tls=%v",
					net.Src(), net.Dst(), sm.From, sm.To, sm.Subject, sm.TLS)
			}
		case "rdp":
			if rm, ok := meta.(*common.RDPMeta); ok {
				log.Printf("[rdp] %s → %s | user=%s client=%s protocols=%s",
					net.Src(), net.Dst(), rm.Cookie, rm.ClientName, rm.ClientBuild)
			}
		case "ntlm":
			if nm, ok := meta.(*common.NTLMMeta); ok {
				log.Printf("[ntlm] %s → %s | domain=%s user=%s host=%s success=%v",
					net.Src(), net.Dst(), nm.Domain, nm.Username, nm.Hostname, nm.Success)
			}
		case "ldap":
			if lm, ok := meta.(*common.LDAPMeta); ok {
				log.Printf("[ldap] %s → %s | base=%s query=%s scope=%s result=%d",
					net.Src(), net.Dst(), lm.BaseObject, lm.Query, lm.QueryScope, lm.ResultCode)
			}
		case "dcerpc":
			if dm, ok := meta.(*common.DCERPCMeta); ok {
				log.Printf("[dcerpc] %s → %s | endpoint=%s op=%s",
					net.Src(), net.Dst(), dm.Endpoint, dm.Operation)
			}
		}

		// Update protocol stats.
		store.Mu.Lock()
		updateProtocolStats(&store.ProtocolStats, protocol)
		store.Mu.Unlock()
	})

	// --- Connection tracker ---
	tracker := sessions.NewTracker(cfg.Sessions, func(sess *common.SessionMeta) {
		log.Printf("[session] %s %s:%d → %s:%d | state=%s dur=%s orig=%d/%d resp=%d/%d cid=%s",
			sess.Transport,
			sess.Flow.SrcIP, sess.Flow.SrcPort,
			sess.Flow.DstIP, sess.Flow.DstPort,
			sess.ConnState, sess.Duration,
			sess.OrigPackets, sess.OrigBytes,
			sess.RespPackets, sess.RespBytes,
			sess.CommunityID)

		// Feed to beacon + exfil + lateral + scan detectors.
		detectionEngine.ProcessSession(sess)
	})
	tracker.StartCleanup()

	// --- Start REST API + Dashboard ---
	srv := api.NewServer(cfg.API.ListenAddr, store, *dashDir)
	go func() {
		if err := srv.Start(); err != nil {
			log.Printf("[api] Server error: %v", err)
		}
	}()
	log.Printf("[dashboard] Open http://localhost%s in your browser", cfg.API.ListenAddr)

	// --- Start capture (if interface/pcap specified) ---
	if cfg.Capture.Interface != "" || *pcapFile != "" {
		engine := capture.NewEngine(cfg.Capture, *pcapFile, 10000)
		if err := engine.Start(); err != nil {
			log.Fatalf("[sensor] Capture start failed: %v", err)
		}

		// Main packet loop.
		pipelineDone := make(chan struct{})
		go func() {
			defer close(pipelineDone)
			count := uint64(0)
			for pkt := range engine.Packets() {
				count++
				tracker.TrackPacket(pkt.Data)
				router.HandlePacket(pkt.Data)

				// Update health stats periodically.
				if count%500 == 0 {
					m := engine.GetMetrics()
					store.Mu.Lock()
					store.Health.PacketsCaptured = m.PacketsReceived
					store.Health.PacketsDropped = m.PacketsDropped
					store.Health.BytesCaptured = m.BytesReceived
					store.Health.PPS = m.PPS()
					store.Health.BPS = m.BPS()
					store.Health.ActiveSessions = tracker.ActiveSessions()
					store.Mu.Unlock()
				}
			}
		}()

		log.Println("[sensor] AkesoNDR sensor started. Waiting for shutdown signal...")
		waitForShutdown()

		log.Println("[sensor] Shutting down...")
		engine.Stop()
		<-pipelineDone
		tracker.Stop()

		// Print summary.
		m := engine.GetMetrics()
		stats := router.Stats()
		created, closed := tracker.Stats()
		log.Printf("[sensor] Capture finished: packets=%d bytes=%d dropped=%d",
			m.PacketsReceived, m.BytesReceived, m.PacketsDropped)
		log.Printf("[sensor] Protocols: dns=%d http=%d tls=%d smb=%d krb=%d ssh=%d smtp=%d rdp=%d ntlm=%d ldap=%d dcerpc=%d unk=%d",
			stats.DNS, stats.HTTP, stats.TLS, stats.SMB, stats.Kerberos,
			stats.SSH, stats.SMTP, stats.RDP, stats.NTLM, stats.LDAP, stats.DCERPC, stats.Unknown)
		log.Printf("[sensor] Sessions: created=%d closed=%d active=%d",
			created, closed, tracker.ActiveSessions())
	} else {
		log.Println("[sensor] No interface or PCAP specified — API-only mode")
		log.Printf("[dashboard] Dashboard at http://localhost%s", cfg.API.ListenAddr)
		waitForShutdown()
	}
}

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[sensor] Received %v", sig)
}

func updateProtocolStats(stats *api.ProtocolStats, protocol string) {
	switch protocol {
	case "dns":
		stats.DNS.Sessions++
	case "http":
		stats.HTTP.Sessions++
	case "tls":
		stats.TLS.Sessions++
	case "smb":
		stats.SMB.Sessions++
	case "kerberos":
		stats.Kerberos.Sessions++
	case "ssh":
		stats.SSH.Sessions++
	case "smtp":
		stats.SMTP.Sessions++
	case "rdp":
		stats.RDP.Sessions++
	case "ntlm":
		stats.NTLM.Sessions++
	case "ldap":
		stats.LDAP.Sessions++
	case "dcerpc":
		stats.DCERPC.Sessions++
	default:
		stats.Unknown.Sessions++
	}
}

func buildHostScores(detections []common.Detection) []common.HostScore {
	hostMap := make(map[string]*common.HostScore)

	for _, d := range detections {
		ip := d.SrcIP
		if ip == "" {
			continue
		}

		h, ok := hostMap[ip]
		if !ok {
			h = &common.HostScore{
				IP:        ip,
				FirstSeen: d.Timestamp,
			}
			hostMap[ip] = h
		}

		h.ActiveDetections++
		h.ThreatScore += int(d.Severity) * 5
		h.CertaintyScore += int(d.Certainty) * 5
		h.LastUpdated = d.Timestamp

		// Track detection types and MITRE tactics.
		typeStr := string(d.Type)
		found := false
		for _, t := range h.DetectionTypes {
			if t == typeStr {
				found = true
				break
			}
		}
		if !found {
			h.DetectionTypes = append(h.DetectionTypes, typeStr)
		}

		if d.MITRE.TacticName != "" {
			tacticFound := false
			for _, t := range h.MITRETacticsObserved {
				if t == d.MITRE.TacticName {
					tacticFound = true
					break
				}
			}
			if !tacticFound {
				h.MITRETacticsObserved = append(h.MITRETacticsObserved, d.MITRE.TacticName)
			}
		}
	}

	// Cap scores and compute quadrants.
	var result []common.HostScore
	for _, h := range hostMap {
		if h.ThreatScore > 100 {
			h.ThreatScore = 100
		}
		if h.CertaintyScore > 100 {
			h.CertaintyScore = 100
		}
		h.Quadrant = common.ComputeQuadrant(h.ThreatScore, h.CertaintyScore)
		result = append(result, *h)
	}
	return result
}

// seedDemoData populates the data store with realistic sample data
// for dashboard demonstration purposes.
func seedDemoData(store *api.DataStore) {
	now := time.Now()

	store.Health = api.SensorHealth{
		Status:          "running",
		StartTime:       now.Add(-2 * time.Hour),
		PacketsCaptured: 2847361,
		PacketsDropped:  12,
		BytesCaptured:   1893247000,
		PPS:             1423,
		BPS:             947000,
		ActiveSessions:  384,
		DetectionEngine: "active",
	}

	store.ProtocolStats = api.ProtocolStats{
		DNS:      api.ProtocolCount{Sessions: 48210, Bytes: 3850000},
		HTTP:     api.ProtocolCount{Sessions: 12450, Bytes: 287000000},
		TLS:      api.ProtocolCount{Sessions: 89340, Bytes: 1450000000},
		SMB:      api.ProtocolCount{Sessions: 3420, Bytes: 45000000},
		Kerberos: api.ProtocolCount{Sessions: 1890, Bytes: 2300000},
		SSH:      api.ProtocolCount{Sessions: 245, Bytes: 12000000},
		SMTP:     api.ProtocolCount{Sessions: 89, Bytes: 450000},
		RDP:      api.ProtocolCount{Sessions: 67, Bytes: 8900000},
		NTLM:     api.ProtocolCount{Sessions: 340, Bytes: 890000},
		LDAP:     api.ProtocolCount{Sessions: 1230, Bytes: 5600000},
		DCERPC:   api.ProtocolCount{Sessions: 890, Bytes: 3400000},
		Unknown:  api.ProtocolCount{Sessions: 4500, Bytes: 23000000},
	}

	store.Detections = []common.Detection{
		{
			ID: "det-demo-001", Name: "C2 Beacon Detected", Type: common.DetectionBeacon,
			Severity: 9, Certainty: 8, SrcIP: "10.10.10.45", DstIP: "198.51.100.23",
			SrcPort: 49832, DstPort: 443, Timestamp: now.Add(-15 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1071.001", TechniqueName: "Web Protocols", TacticID: "TA0011", TacticName: "Command and Control"},
			Evidence: map[string]any{"interval_mean": 30.2, "interval_stddev": 1.4, "sessions": 48, "ja3": "a0e9f5d64349fb13191bc781f81f42e1"},
		},
		{
			ID: "det-demo-002", Name: "DNS Tunneling Suspected", Type: common.DetectionDNSTunnel,
			Severity: 7, Certainty: 8, SrcIP: "10.10.10.45", DstIP: "10.10.10.10",
			SrcPort: 52341, DstPort: 53, Timestamp: now.Add(-12 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1071.004", TechniqueName: "DNS", TacticID: "TA0011", TacticName: "Command and Control"},
			Evidence: map[string]any{"entropy": 4.82, "subdomain_depth": 8, "parent_domain": "c2-tunnel.evil.com", "query_count": 347},
		},
		{
			ID: "det-demo-003", Name: "Lateral Movement — SMB Admin Share", Type: common.DetectionLateralMovement,
			Severity: 9, Certainty: 9, SrcIP: "10.10.10.45", DstIP: "10.10.10.20",
			SrcPort: 49901, DstPort: 445, Timestamp: now.Add(-8 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1021.002", TechniqueName: "SMB/Windows Admin Shares", TacticID: "TA0008", TacticName: "Lateral Movement"},
			Evidence: map[string]any{"share": "\\\\10.10.10.20\\ADMIN$", "fan_out": 3, "smb_action": "tree_connect_admin_share"},
		},
		{
			ID: "det-demo-004", Name: "Kerberoasting Detected", Type: common.DetectionKerberoasting,
			Severity: 8, Certainty: 9, SrcIP: "10.10.10.45", DstIP: "10.10.10.10",
			SrcPort: 49455, DstPort: 88, Timestamp: now.Add(-20 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1558.003", TechniqueName: "Kerberoasting", TacticID: "TA0006", TacticName: "Credential Access"},
			Evidence: map[string]any{"tgs_requests": 24, "rc4_requests": 22, "window": "5m", "targeted_spns": "MSSQLSvc/db01.akeso.lab:1433,HTTP/web01.akeso.lab"},
		},
		{
			ID: "det-demo-005", Name: "Data Exfiltration — High Volume Outbound", Type: common.DetectionExfiltration,
			Severity: 8, Certainty: 7, SrcIP: "10.10.10.45", DstIP: "203.0.113.50",
			SrcPort: 50123, DstPort: 443, Timestamp: now.Add(-3 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1041", TechniqueName: "Exfiltration Over C2 Channel", TacticID: "TA0010", TacticName: "Exfiltration"},
			Evidence: map[string]any{"bytes_out": 524288000, "baseline_bytes": 12000000, "deviation": 4.3, "duration": "12m"},
		},
		{
			ID: "det-demo-006", Name: "Port Scan Detected", Type: common.DetectionPortScan,
			Severity: 4, Certainty: 9, SrcIP: "10.10.10.99", DstIP: "10.10.10.0/24",
			SrcPort: 0, DstPort: 0, Timestamp: now.Add(-45 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1046", TechniqueName: "Network Service Discovery", TacticID: "TA0007", TacticName: "Discovery"},
			Evidence: map[string]any{"scan_type": "horizontal", "ports_scanned": 1024, "hosts_scanned": 15, "s0_connections": 890},
		},
		{
			ID: "det-demo-007", Name: "Lateral Movement — WMI Remote Exec", Type: common.DetectionRemoteExec,
			Severity: 8, Certainty: 7, SrcIP: "10.10.10.45", DstIP: "10.10.10.30",
			SrcPort: 49920, DstPort: 135, Timestamp: now.Add(-6 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1047", TechniqueName: "Windows Management Instrumentation", TacticID: "TA0002", TacticName: "Execution"},
			Evidence: map[string]any{"endpoint": "IWbemLoginClientID", "operation": "NTLMLogin"},
		},
		{
			ID: "det-demo-008", Name: "C2 Beacon Detected", Type: common.DetectionBeacon,
			Severity: 6, Certainty: 5, SrcIP: "10.10.10.22", DstIP: "192.0.2.100",
			SrcPort: 51200, DstPort: 8443, Timestamp: now.Add(-30 * time.Minute),
			MITRE: common.MITRETechnique{TechniqueID: "T1573", TechniqueName: "Encrypted Channel", TacticID: "TA0011", TacticName: "Command and Control"},
			Evidence: map[string]any{"interval_mean": 60.5, "interval_stddev": 8.2, "sessions": 14},
		},
	}

	store.Hosts = buildHostScores(store.Detections)

	store.SignatureCount = 2847
	store.SignatureErrors = 3
}
