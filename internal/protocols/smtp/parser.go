// Package smtp implements the AkesoNDR SMTP protocol dissector.
//
// It parses SMTP envelope commands (HELO/EHLO, MAIL FROM, RCPT TO) and
// extracts headers from the DATA section, producing metadata defined in
// REQUIREMENTS.md Section 4.7: from, to, cc, subject, DKIM/DMARC/SPF
// status, and TLS flag (STARTTLS detection).
package smtp

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// Parser extracts SMTP metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates an SMTP parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts SMTPMeta from client and server stream data.
// Returns nil if the data does not contain SMTP traffic.
func (p *Parser) Parse(client, server []byte) *common.SMTPMeta {
	if len(client) == 0 && len(server) == 0 {
		return nil
	}

	// Verify this looks like SMTP: server starts with 220, or client has EHLO/HELO.
	if !p.CanParse(client) && !looksLikeSMTPServer(server) {
		return nil
	}

	meta := &common.SMTPMeta{}

	// Parse client commands.
	scanner := bufio.NewScanner(bytes.NewReader(client))
	inData := false
	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()
		upper := strings.ToUpper(line)

		if inData {
			if line == "." {
				inData = false
				continue
			}
			dataLines = append(dataLines, line)
			continue
		}

		switch {
		case strings.HasPrefix(upper, "MAIL FROM:"):
			meta.From = extractAddr(line[10:])
		case strings.HasPrefix(upper, "RCPT TO:"):
			meta.To = append(meta.To, extractAddr(line[8:]))
		case strings.HasPrefix(upper, "STARTTLS"):
			meta.TLS = true
		case upper == "DATA":
			inData = true
		}
	}

	// Parse email headers from DATA section.
	parseHeaders(dataLines, meta)

	// Check server responses for STARTTLS support.
	if bytes.Contains(server, []byte("STARTTLS")) {
		meta.TLS = true
	}

	return meta
}

// CanParse returns true if the client data starts with SMTP commands.
func (p *Parser) CanParse(client []byte) bool {
	if len(client) < 4 {
		return false
	}
	upper := strings.ToUpper(string(client[:min(10, len(client))]))
	return strings.HasPrefix(upper, "EHLO ") ||
		strings.HasPrefix(upper, "HELO ") ||
		strings.HasPrefix(upper, "MAIL ")
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func looksLikeSMTPServer(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// SMTP server greeting starts with "220 ".
	return bytes.HasPrefix(data, []byte("220 ")) || bytes.HasPrefix(data, []byte("220-"))
}

func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	// Strip angle brackets: <user@example.com> → user@example.com
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	// Strip SMTP parameters after space (e.g., "SIZE=1234").
	if idx := strings.IndexByte(s, ' '); idx > 0 {
		s = s[:idx]
	}
	return s
}

func parseHeaders(lines []string, meta *common.SMTPMeta) {
	for _, line := range lines {
		lower := strings.ToLower(line)

		switch {
		case strings.HasPrefix(lower, "subject:"):
			meta.Subject = strings.TrimSpace(line[8:])
		case strings.HasPrefix(lower, "cc:"):
			addrs := strings.Split(line[3:], ",")
			for _, a := range addrs {
				a = extractAddr(a)
				if a != "" {
					meta.CC = append(meta.CC, a)
				}
			}
		case strings.HasPrefix(lower, "dkim-signature:"):
			if meta.DKIMStatus != "pass" && meta.DKIMStatus != "fail" {
				meta.DKIMStatus = "present"
			}
		case strings.HasPrefix(lower, "authentication-results:"):
			parseAuthResults(line, meta)
		}

		// Empty line = end of headers.
		if line == "" {
			break
		}
	}
}

func parseAuthResults(line string, meta *common.SMTPMeta) {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "dkim=pass") {
		meta.DKIMStatus = "pass"
	} else if strings.Contains(lower, "dkim=fail") {
		meta.DKIMStatus = "fail"
	}
	if strings.Contains(lower, "spf=pass") {
		meta.SPFStatus = "pass"
	} else if strings.Contains(lower, "spf=fail") {
		meta.SPFStatus = "fail"
	}
	if strings.Contains(lower, "dmarc=pass") {
		meta.DMARCStatus = "pass"
	} else if strings.Contains(lower, "dmarc=fail") {
		meta.DMARCStatus = "fail"
	}
}
