// Package protocols implements the AkesoNDR protocol router.
//
// The router classifies network sessions by port number and payload heuristics,
// then dispatches to the correct protocol dissector. It implements the
// capture.StreamHandler interface to receive reassembled TCP streams from the
// TCP reassembly engine, and also provides a method for processing individual
// UDP packets (e.g., DNS).
package protocols

import (
	"encoding/binary"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	ndrdns "github.com/akesondr/akeso-ndr/internal/protocols/dns"
	ndrhttp "github.com/akesondr/akeso-ndr/internal/protocols/http"
	ndrkrb "github.com/akesondr/akeso-ndr/internal/protocols/kerberos"
	ndrntlm "github.com/akesondr/akeso-ndr/internal/protocols/ntlm"
	ndrrdp "github.com/akesondr/akeso-ndr/internal/protocols/rdp"
	ndrsmb "github.com/akesondr/akeso-ndr/internal/protocols/smb"
	ndrsmtp "github.com/akesondr/akeso-ndr/internal/protocols/smtp"
	ndrssh "github.com/akesondr/akeso-ndr/internal/protocols/ssh"
	ndrtls "github.com/akesondr/akeso-ndr/internal/protocols/tls"
)

// MetadataCallback is called when a protocol dissector produces metadata.
type MetadataCallback func(meta any, protocol string, net, transport gopacket.Flow)

// Router classifies and dispatches to protocol dissectors.
type Router struct {
	mu       sync.RWMutex
	dns      *ndrdns.Parser
	http     *ndrhttp.Parser
	tls      *ndrtls.Parser
	smb      *ndrsmb.Parser
	kerberos *ndrkrb.Parser
	ssh      *ndrssh.Parser
	smtp     *ndrsmtp.Parser
	rdp      *ndrrdp.Parser
	ntlm     *ndrntlm.Parser
	callback MetadataCallback

	// Stats
	stats RouterStats
}

// RouterStats tracks protocol classification counts.
type RouterStats struct {
	DNS      uint64 `json:"dns"`
	HTTP     uint64 `json:"http"`
	TLS      uint64 `json:"tls"`
	SMB      uint64 `json:"smb"`
	Kerberos uint64 `json:"kerberos"`
	SSH      uint64 `json:"ssh"`
	SMTP     uint64 `json:"smtp"`
	RDP      uint64 `json:"rdp"`
	NTLM     uint64 `json:"ntlm"`
	Unknown  uint64 `json:"unknown"`
}

// NewRouter creates a protocol router with all available dissectors.
func NewRouter(callback MetadataCallback) *Router {
	return &Router{
		dns:      ndrdns.NewParser(),
		http:     ndrhttp.NewParser(),
		tls:      ndrtls.NewParser(),
		smb:      ndrsmb.NewParser(),
		kerberos: ndrkrb.NewParser(),
		ssh:      ndrssh.NewParser(),
		smtp:     ndrsmtp.NewParser(),
		rdp:      ndrrdp.NewParser(),
		ntlm:     ndrntlm.NewParser(),
		callback: callback,
	}
}

// HandleStream implements capture.StreamHandler. It receives reassembled
// bidirectional TCP stream data and routes to the appropriate dissector.
func (r *Router) HandleStream(net, transport gopacket.Flow, client, server []byte) {
	dstPort := dstPortFromFlow(transport)

	protocol := r.classifyTCP(dstPort, client, server)

	switch protocol {
	case "http":
		meta := r.http.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.HTTP)
			if r.callback != nil {
				r.callback(meta, "http", net, transport)
			}
			return
		}

	case "tls":
		meta := r.tls.Parse(client, server)
		r.incStat(&r.stats.TLS)
		if r.callback != nil {
			r.callback(meta, "tls", net, transport)
		}
		return

	case "smb":
		meta := r.smb.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.SMB)
			if r.callback != nil {
				r.callback(meta, "smb", net, transport)
			}
			return
		}

	case "kerberos":
		meta := r.kerberos.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.Kerberos)
			if r.callback != nil {
				r.callback(meta, "kerberos", net, transport)
			}
			return
		}

	case "ssh":
		meta := r.ssh.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.SSH)
			if r.callback != nil {
				r.callback(meta, "ssh", net, transport)
			}
			return
		}

	case "smtp":
		meta := r.smtp.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.SMTP)
			if r.callback != nil {
				r.callback(meta, "smtp", net, transport)
			}
			return
		}

	case "rdp":
		meta := r.rdp.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.RDP)
			if r.callback != nil {
				r.callback(meta, "rdp", net, transport)
			}
			return
		}
	}

	// Check for NTLM within any stream (it piggybacks on SMB, HTTP, etc.).
	if r.ntlm.CanParse(client) || r.ntlm.CanParse(server) {
		meta := r.ntlm.Parse(client, server)
		if meta != nil {
			r.incStat(&r.stats.NTLM)
			if r.callback != nil {
				r.callback(meta, "ntlm", net, transport)
			}
		}
		// Don't return — let the primary protocol also be counted.
	}

	// Unknown/unhandled protocol.
	r.incStat(&r.stats.Unknown)
}

// HandlePacket processes a single packet for non-TCP protocols (primarily DNS
// over UDP). Called directly by the capture pipeline for each UDP packet.
func (r *Router) HandlePacket(pkt gopacket.Packet) {
	// Check for DNS (UDP port 53 or DNS layer present).
	if r.dns.CanParse(pkt) {
		meta := r.dns.Parse(pkt)
		if meta != nil {
			r.incStat(&r.stats.DNS)
			if r.callback != nil {
				var netFlow, transFlow gopacket.Flow
				if nl := pkt.NetworkLayer(); nl != nil {
					netFlow = nl.NetworkFlow()
				}
				if tl := pkt.TransportLayer(); tl != nil {
					transFlow = tl.TransportFlow()
				}
				r.callback(meta, "dns", netFlow, transFlow)
			}
		}
		return
	}

	// Kerberos can also be over UDP (port 88).
	if tl := pkt.TransportLayer(); tl != nil {
		if udp, ok := tl.(*layers.UDP); ok {
			if uint16(udp.SrcPort) == 88 || uint16(udp.DstPort) == 88 {
				payload := udp.LayerPayload()
				if r.kerberos.CanParse(payload) {
					meta := r.kerberos.ParsePacketData(payload)
					if meta != nil {
						r.incStat(&r.stats.Kerberos)
						if r.callback != nil {
							var netFlow, transFlow gopacket.Flow
							if nl := pkt.NetworkLayer(); nl != nil {
								netFlow = nl.NetworkFlow()
							}
							transFlow = tl.TransportFlow()
							r.callback(meta, "kerberos", netFlow, transFlow)
						}
					}
					return
				}
			}
		}
	}

	// Future: ICMP, other UDP protocols.
	r.incStat(&r.stats.Unknown)
}

// Stats returns a snapshot of protocol classification counts.
func (r *Router) Stats() RouterStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stats
}

func (r *Router) incStat(counter *uint64) {
	r.mu.Lock()
	*counter++
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Classification logic
// ---------------------------------------------------------------------------

// classifyTCP determines the application protocol for a TCP stream using
// port-based hints and payload heuristics.
func (r *Router) classifyTCP(dstPort uint16, client, server []byte) string {
	// 1. Payload heuristics (most reliable).
	if len(client) > 0 {
		// TLS: ClientHello starts with 0x16 0x03 (handshake + TLS version).
		if isTLSClientHello(client) {
			return "tls"
		}

		// HTTP: starts with a method keyword.
		if r.http.CanParse(client) {
			return "http"
		}

		// SMB: look for SMB magic bytes.
		if r.smb.CanParse(client) {
			return "smb"
		}

		// Kerberos: ASN.1 APPLICATION tags for KDC messages.
		if r.kerberos.CanParse(client) {
			return "kerberos"
		}

		// SSH: starts with "SSH-".
		if r.ssh.CanParse(client) {
			return "ssh"
		}

		// SMTP: starts with EHLO/HELO/MAIL.
		if r.smtp.CanParse(client) {
			return "smtp"
		}

		// RDP: TPKT + X.224 or mstshash cookie.
		if r.rdp.CanParse(client) {
			return "rdp"
		}
	}

	// Also check server data for protocols where server responds first.
	if len(server) > 0 {
		if r.smb.CanParse(server) {
			return "smb"
		}
		if r.kerberos.CanParse(server) {
			return "kerberos"
		}
		if r.ssh.CanParse(server) {
			return "ssh"
		}
	}

	// 2. Port-based fallback.
	switch dstPort {
	case 80, 8080, 8000, 8888:
		return "http"
	case 443, 8443:
		return "tls"
	case 445, 139:
		return "smb"
	case 88:
		return "kerberos"
	case 22:
		return "ssh"
	case 25, 587, 465:
		return "smtp"
	case 3389:
		return "rdp"
	}

	return "unknown"
}

// isTLSClientHello checks if data starts with a TLS handshake record
// (content type 0x16 = Handshake, version 0x0301-0x0304).
func isTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	if data[0] != 0x16 {
		return false
	}
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0300 || version > 0x0304 {
		return false
	}
	if data[5] == 0x01 {
		return true
	}
	return false
}

// dstPortFromFlow extracts the destination port from a transport flow.
func dstPortFromFlow(transport gopacket.Flow) uint16 {
	dst := transport.Dst()
	raw := dst.Raw()
	if len(raw) == 2 {
		return binary.BigEndian.Uint16(raw)
	}
	return 0
}

// classifyPacketProtocol returns the protocol name for a single packet
// based on port numbers. Used for UDP classification.
func classifyPacketProtocol(pkt gopacket.Packet) string {
	if tl := pkt.TransportLayer(); tl != nil {
		switch tp := tl.(type) {
		case *layers.UDP:
			srcPort := uint16(tp.SrcPort)
			dstPort := uint16(tp.DstPort)
			if srcPort == 53 || dstPort == 53 {
				return "dns"
			}
			if srcPort == 88 || dstPort == 88 {
				return "kerberos"
			}
		}
	}
	return "unknown"
}
