// Package tls implements the AkesoNDR TLS protocol dissector.
//
// It parses TLS ClientHello and ServerHello messages from raw TCP stream data,
// extracting metadata defined in REQUIREMENTS.md Section 4.3: TLS version,
// cipher suite, SNI, JA3/JA3S fingerprints, certificate fields, ALPN, and
// client extensions. The parser operates on reassembled byte slices, not
// live packets, since TLS data arrives via the TCP reassembly engine.
package tls

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// TLS record and handshake constants.
const (
	recordTypeHandshake  = 0x16
	handshakeClientHello = 0x01
	handshakeServerHello = 0x02
	handshakeCertificate = 0x0B

	extSNI  = 0x0000
	extALPN = 0x0010
)

// Parser extracts TLS metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates a TLS parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts TLSMeta from client and server stream data.
// Returns nil if the data does not contain a TLS handshake.
func (p *Parser) Parse(client, server []byte) *common.TLSMeta {
	if len(client) < 6 {
		return nil
	}

	// Verify TLS record header.
	if client[0] != recordTypeHandshake {
		return nil
	}

	meta := &common.TLSMeta{}

	// Parse ClientHello.
	ch := parseClientHello(client)
	if ch == nil {
		return nil
	}

	meta.ServerName = ch.sni
	meta.ClientExtensions = ch.extensions
	meta.JA3 = computeJA3(ch)

	// Parse ServerHello if available.
	if len(server) > 5 && server[0] == recordTypeHandshake {
		sh := parseServerHello(server)
		if sh != nil {
			meta.Version = versionName(sh.version)
			meta.Cipher = cipherName(sh.cipher)
			meta.Established = true
			meta.JA3S = computeJA3S(sh)

			// Look for certificate after ServerHello.
			cert := parseCertificateRecord(server)
			if cert != nil {
				meta.Subject = cert.subject
				meta.Issuer = cert.issuer
				meta.SANDNSNames = cert.sanDNS
				meta.NotValidBefore = cert.notBefore
				meta.NotValidAfter = cert.notAfter
			}
		}
	} else {
		// No server response — use ClientHello version.
		meta.Version = versionName(ch.version)
	}

	// Extract ALPN from ClientHello extensions.
	if ch.alpn != "" {
		meta.NextProtocol = ch.alpn
	}

	return meta
}

// CanParse returns true if the client data starts with a TLS handshake record.
func (p *Parser) CanParse(client []byte) bool {
	if len(client) < 6 {
		return false
	}
	if client[0] != recordTypeHandshake {
		return false
	}
	version := binary.BigEndian.Uint16(client[1:3])
	return version >= 0x0300 && version <= 0x0304 && client[5] == handshakeClientHello
}

// ---------------------------------------------------------------------------
// ClientHello parsing
// ---------------------------------------------------------------------------

type clientHello struct {
	version      uint16
	cipherSuites []uint16
	extensions   []uint16
	sni          string
	alpn         string
	// For JA3: elliptic curves and EC point formats
	ellipticCurves []uint16
	ecPointFormats []uint8
}

func parseClientHello(data []byte) *clientHello {
	// TLS record: type(1) + version(2) + length(2) + handshake...
	if len(data) < 5 {
		return nil
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) < recordLen {
		payload = payload[:len(payload)] // use what we have
	}

	if len(payload) < 1 || payload[0] != handshakeClientHello {
		return nil
	}

	// Handshake: type(1) + length(3) + version(2) + random(32) + ...
	if len(payload) < 6 {
		return nil
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	_ = hsLen

	off := 4 // past handshake type + length
	if off+2 > len(payload) {
		return nil
	}
	ch := &clientHello{
		version: binary.BigEndian.Uint16(payload[off : off+2]),
	}
	off += 2

	// Random (32 bytes).
	off += 32
	if off >= len(payload) {
		return nil
	}

	// Session ID.
	sidLen := int(payload[off])
	off += 1 + sidLen
	if off+2 > len(payload) {
		return ch
	}

	// Cipher suites.
	csLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if off+csLen > len(payload) {
		return ch
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(payload[off+i : off+i+2])
		// Skip GREASE values.
		if !isGREASE(cs) {
			ch.cipherSuites = append(ch.cipherSuites, cs)
		}
	}
	off += csLen

	// Compression methods.
	if off >= len(payload) {
		return ch
	}
	compLen := int(payload[off])
	off += 1 + compLen

	// Extensions.
	if off+2 > len(payload) {
		return ch
	}
	extLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	extEnd := off + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		off += 4
		if off+extDataLen > extEnd {
			break
		}
		extData := payload[off : off+extDataLen]

		if !isGREASE(extType) {
			ch.extensions = append(ch.extensions, extType)
		}

		switch extType {
		case extSNI:
			ch.sni = parseSNI(extData)
		case extALPN:
			ch.alpn = parseALPN(extData)
		case 0x000a: // supported_groups (elliptic_curves)
			ch.ellipticCurves = parseSupportedGroups(extData)
		case 0x000b: // ec_point_formats
			ch.ecPointFormats = parseECPointFormats(extData)
		}

		off += extDataLen
	}

	return ch
}

// ---------------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------------

type serverHello struct {
	version    uint16
	cipher     uint16
	extensions []uint16
}

func parseServerHello(data []byte) *serverHello {
	// Find ServerHello in possibly multi-record data.
	off := 0
	for off+5 < len(data) {
		if data[off] != recordTypeHandshake {
			break
		}
		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		payload := data[off+5:]
		if len(payload) > recLen {
			payload = payload[:recLen]
		}

		if len(payload) > 0 && payload[0] == handshakeServerHello {
			return parseServerHelloPayload(payload)
		}

		off += 5 + recLen
	}
	return nil
}

func parseServerHelloPayload(payload []byte) *serverHello {
	if len(payload) < 39 { // min ServerHello size
		return nil
	}

	off := 4 // past type(1) + length(3)
	sh := &serverHello{
		version: binary.BigEndian.Uint16(payload[off : off+2]),
	}
	off += 2

	// Random (32 bytes).
	off += 32

	// Session ID.
	if off >= len(payload) {
		return sh
	}
	sidLen := int(payload[off])
	off += 1 + sidLen

	// Cipher suite.
	if off+2 > len(payload) {
		return sh
	}
	sh.cipher = binary.BigEndian.Uint16(payload[off : off+2])
	off += 2

	// Compression method.
	off += 1

	// Extensions.
	if off+2 > len(payload) {
		return sh
	}
	extLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	extEnd := off + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		off += 4
		if !isGREASE(extType) {
			sh.extensions = append(sh.extensions, extType)
		}
		off += extDataLen
	}

	return sh
}

// ---------------------------------------------------------------------------
// Certificate parsing (minimal — extract subject/issuer from first cert)
// ---------------------------------------------------------------------------

type certInfo struct {
	subject   string
	issuer    string
	sanDNS    []string
	notBefore common.Timestamp
	notAfter  common.Timestamp
}

func parseCertificateRecord(data []byte) *certInfo {
	// Scan records for Certificate handshake type.
	off := 0
	for off+5 < len(data) {
		if data[off] != recordTypeHandshake {
			break
		}
		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		payload := data[off+5:]
		if len(payload) > recLen {
			payload = payload[:recLen]
		}

		if len(payload) > 0 && payload[0] == handshakeCertificate {
			// Certificate message found — we note it but full X.509
			// parsing is complex. For POC, just flag that certs were seen.
			return &certInfo{
				subject: "(certificate present)",
				issuer:  "(certificate present)",
			}
		}

		off += 5 + recLen
	}
	return nil
}

// ---------------------------------------------------------------------------
// JA3 / JA3S computation
// ---------------------------------------------------------------------------

// computeJA3 produces the JA3 hash from a ClientHello.
// JA3 = md5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
func computeJA3(ch *clientHello) string {
	parts := []string{
		fmt.Sprintf("%d", ch.version),
		joinUint16(ch.cipherSuites),
		joinUint16(ch.extensions),
		joinUint16(ch.ellipticCurves),
		joinUint8(ch.ecPointFormats),
	}
	raw := strings.Join(parts, ",")
	hash := md5.Sum([]byte(raw))
	return fmt.Sprintf("%x", hash[:])
}

// computeJA3S produces the JA3S hash from a ServerHello.
// JA3S = md5(TLSVersion,CipherSuite,Extensions)
func computeJA3S(sh *serverHello) string {
	parts := []string{
		fmt.Sprintf("%d", sh.version),
		fmt.Sprintf("%d", sh.cipher),
		joinUint16(sh.extensions),
	}
	raw := strings.Join(parts, ",")
	hash := md5.Sum([]byte(raw))
	return fmt.Sprintf("%x", hash[:])
}

// ---------------------------------------------------------------------------
// Extension parsers
// ---------------------------------------------------------------------------

func parseSNI(data []byte) string {
	// SNI extension: list_length(2) + type(1) + name_length(2) + name
	if len(data) < 5 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPN(data []byte) string {
	// ALPN extension: list_length(2) + string_length(1) + string
	if len(data) < 4 {
		return ""
	}
	strLen := int(data[2])
	if 3+strLen > len(data) {
		return ""
	}
	return string(data[3 : 3+strLen])
}

func parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	var groups []uint16
	for i := 2; i+1 < 2+listLen && i+1 < len(data); i += 2 {
		g := binary.BigEndian.Uint16(data[i : i+2])
		if !isGREASE(g) {
			groups = append(groups, g)
		}
	}
	return groups
}

func parseECPointFormats(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	fmtLen := int(data[0])
	var formats []uint8
	for i := 1; i < 1+fmtLen && i < len(data); i++ {
		formats = append(formats, data[i])
	}
	return formats
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isGREASE(v uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, ..., 0xfafa
	return (v & 0x0f0f) == 0x0a0a
}

func versionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func cipherName(c uint16) string {
	// Common cipher suite names.
	names := map[uint16]string{
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	}
	if name, ok := names[c]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", c)
}

func joinUint16(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinUint8(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}
