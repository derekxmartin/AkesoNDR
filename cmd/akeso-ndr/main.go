package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/akesondr/akeso-ndr/internal/capture"
	"github.com/akesondr/akeso-ndr/internal/config"

	// Blank imports to verify all packages compile.
	_ "github.com/akesondr/akeso-ndr/internal/api"
	_ "github.com/akesondr/akeso-ndr/internal/common"
	_ "github.com/akesondr/akeso-ndr/internal/detect"
	_ "github.com/akesondr/akeso-ndr/internal/export"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dcerpc"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dns"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/http"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/kerberos"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ldap"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ntlm"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/rdp"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/smb"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/smtp"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/ssh"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/tls"
	_ "github.com/akesondr/akeso-ndr/internal/sessions"
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

	// Create and start capture engine.
	engine := capture.NewEngine(cfg.Capture, *pcapFile, 10000)
	if err := engine.Start(); err != nil {
		log.Fatalf("[sensor] Capture start failed: %v", err)
	}

	// Drain packets (log summary). In later phases this feeds the
	// protocol router, session tracker, and detection engine.
	go func() {
		count := uint64(0)
		for pkt := range engine.Packets() {
			_ = pkt // Will be consumed by downstream components.
			count++
			if count%1000 == 0 {
				m := engine.GetMetrics()
				log.Printf("[sensor] Processed %d packets (pps=%.0f bps=%.0f)",
					m.PacketsReceived, m.PPS(), m.BPS())
			}
		}
		m := engine.GetMetrics()
		log.Printf("[sensor] Capture finished: packets=%d bytes=%d dropped=%d",
			m.PacketsReceived, m.BytesReceived, m.PacketsDropped)
	}()

	log.Println("[sensor] AkesoNDR sensor started. Waiting for shutdown signal...")
	waitForShutdown()

	log.Println("[sensor] Shutting down capture engine...")
	engine.Stop()
}

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[sensor] Received %v", sig)
}
