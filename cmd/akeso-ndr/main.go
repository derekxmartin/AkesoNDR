package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/akesondr/akeso-ndr/internal/api"
	_ "github.com/akesondr/akeso-ndr/internal/capture"
	_ "github.com/akesondr/akeso-ndr/internal/common"
	_ "github.com/akesondr/akeso-ndr/internal/config"
	_ "github.com/akesondr/akeso-ndr/internal/detect"
	_ "github.com/akesondr/akeso-ndr/internal/export"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dcerpc"
	_ "github.com/akesondr/akeso-ndr/internal/protocols/dns"
	ndrhttp "github.com/akesondr/akeso-ndr/internal/protocols/http"
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

// Blank import to verify all packages compile.
var _ = ndrhttp.Placeholder

func main() {
	iface := flag.String("interface", "", "Network interface to capture on (e.g. eth0)")
	pcapFile := flag.String("pcap", "", "Path to PCAP file for offline replay")
	flag.Parse()

	fmt.Println("AkesoNDR — Network Detection & Response")
	fmt.Printf("Version: %s\n", version)

	if *iface != "" {
		log.Printf("[sensor] Capture interface: %s", *iface)
	} else if *pcapFile != "" {
		log.Printf("[sensor] Offline PCAP replay: %s", *pcapFile)
	} else {
		log.Println("[sensor] No interface or PCAP specified — running in standby mode")
	}

	log.Println("[sensor] AkesoNDR sensor started. Waiting for shutdown signal...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[sensor] Received %v — shutting down gracefully", sig)
}
