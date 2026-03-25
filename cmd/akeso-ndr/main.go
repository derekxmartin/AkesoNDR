package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"

	"github.com/akesondr/akeso-ndr/internal/capture"
	"github.com/akesondr/akeso-ndr/internal/common"
	"github.com/akesondr/akeso-ndr/internal/config"
	"github.com/akesondr/akeso-ndr/internal/protocols"
	"github.com/akesondr/akeso-ndr/internal/sessions"

	// Blank imports to verify all packages compile.
	_ "github.com/akesondr/akeso-ndr/internal/api"
	_ "github.com/akesondr/akeso-ndr/internal/detect"
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

	// Determine mode.
	if cfg.Capture.Interface == "" && *pcapFile == "" {
		log.Println("[sensor] No interface or PCAP specified — running in standby mode")
		waitForShutdown()
		return
	}

	// --- Protocol router: logs metadata as it's extracted ---
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
		}
	})

	// --- Connection tracker: logs session close events ---
	tracker := sessions.NewTracker(cfg.Sessions, func(sess *common.SessionMeta) {
		log.Printf("[session] %s %s:%d → %s:%d | state=%s dur=%s orig=%d/%d resp=%d/%d cid=%s",
			sess.Transport,
			sess.Flow.SrcIP, sess.Flow.SrcPort,
			sess.Flow.DstIP, sess.Flow.DstPort,
			sess.ConnState, sess.Duration,
			sess.OrigPackets, sess.OrigBytes,
			sess.RespPackets, sess.RespBytes,
			sess.CommunityID)
	})
	tracker.StartCleanup()

	// Create and start capture engine.
	engine := capture.NewEngine(cfg.Capture, *pcapFile, 10000)
	if err := engine.Start(); err != nil {
		log.Fatalf("[sensor] Capture start failed: %v", err)
	}

	// --- Main packet loop: feed packets through tracker + router ---
	pipelineDone := make(chan struct{})
	go func() {
		defer close(pipelineDone)
		count := uint64(0)
		for pkt := range engine.Packets() {
			count++

			// Feed to connection tracker.
			tracker.TrackPacket(pkt.Data)

			// Feed to protocol router (UDP packets like DNS).
			router.HandlePacket(pkt.Data)

			if count%1000 == 0 {
				m := engine.GetMetrics()
				log.Printf("[sensor] Processed %d packets (pps=%.0f bps=%.0f)",
					m.PacketsReceived, m.PPS(), m.BPS())
			}
		}
	}()

	log.Println("[sensor] AkesoNDR sensor started. Waiting for shutdown signal...")
	waitForShutdown()

	log.Println("[sensor] Shutting down...")
	engine.Stop()
	<-pipelineDone // Wait for packet loop to drain.
	tracker.Stop()

	// Print summary.
	m := engine.GetMetrics()
	stats := router.Stats()
	created, closed := tracker.Stats()
	log.Printf("[sensor] Capture finished: packets=%d bytes=%d dropped=%d",
		m.PacketsReceived, m.BytesReceived, m.PacketsDropped)
	log.Printf("[sensor] Protocols: dns=%d http=%d tls=%d smb=%d krb=%d ssh=%d smtp=%d rdp=%d ntlm=%d unk=%d",
		stats.DNS, stats.HTTP, stats.TLS, stats.SMB, stats.Kerberos,
		stats.SSH, stats.SMTP, stats.RDP, stats.NTLM, stats.Unknown)
	log.Printf("[sensor] Sessions: created=%d closed=%d active=%d",
		created, closed, tracker.ActiveSessions())
}

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[sensor] Received %v", sig)
}
