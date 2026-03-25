// Package dns implements the AkesoNDR DNS protocol dissector.
//
// It parses DNS queries and responses from both UDP (port 53) and TCP
// transport, extracts all metadata fields defined in REQUIREMENTS.md
// Section 4.1, and computes NDR-specific enrichment fields: Shannon entropy
// of the query name, subdomain depth, and query length. These enrichment
// fields are critical inputs for the DNS tunneling detector (Section 5.2).
package dns

import (
	"math"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/akesondr/akeso-ndr/internal/common"
)

// Parser extracts DNS metadata from packets.
type Parser struct{}

// NewParser creates a DNS parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts DNSMeta from a gopacket.Packet containing a DNS layer.
// Returns nil if the packet does not contain DNS.
func (p *Parser) Parse(pkt gopacket.Packet) *common.DNSMeta {
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil
	}

	meta := &common.DNSMeta{
		TransID:      dns.ID,
		AA:           dns.AA,
		RD:           dns.RD,
		RA:           dns.RA,
		TC:           dns.TC,
		RCode:        uint16(dns.ResponseCode),
		RCodeName:    rcodeToName(dns.ResponseCode),
		TotalAnswers: int(dns.ANCount),
	}

	// Determine transport.
	if pkt.Layer(layers.LayerTypeTCP) != nil {
		meta.Proto = "tcp"
	} else {
		meta.Proto = "udp"
	}

	// Extract question fields.
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		meta.Query = string(q.Name)
		meta.QType = uint16(q.Type)
		meta.QTypeName = qtypeToName(q.Type)
		meta.QClass = uint16(q.Class)
		meta.QClassName = qclassToName(q.Class)

		// NDR-computed enrichment fields.
		meta.QueryLength = len(meta.Query)
		meta.Entropy = ShannonEntropy(meta.Query)
		meta.SubdomainDepth = SubdomainDepth(meta.Query)
	}

	// Extract answer records.
	for _, ans := range dns.Answers {
		answer := common.DNSAnswer{
			Type: qtypeToName(ans.Type),
			TTL:  ans.TTL,
		}

		// Extract answer data based on type.
		switch ans.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if ans.IP != nil {
				answer.Data = ans.IP.String()
			}
		case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
			answer.Data = string(ans.CNAME)
		case layers.DNSTypeMX:
			answer.Data = string(ans.MX.Name)
		case layers.DNSTypeTXT:
			var parts []string
			for _, txt := range ans.TXTs {
				parts = append(parts, string(txt))
			}
			answer.Data = strings.Join(parts, " ")
		case layers.DNSTypeSRV:
			answer.Data = string(ans.SRV.Name)
		case layers.DNSTypeSOA:
			answer.Data = string(ans.SOA.MName)
		default:
			answer.Data = string(ans.Name)
		}

		meta.Answers = append(meta.Answers, answer)
		meta.TTLs = append(meta.TTLs, ans.TTL)
	}

	return meta
}

// CanParse returns true if the packet contains a DNS layer.
func (p *Parser) CanParse(pkt gopacket.Packet) bool {
	return pkt.Layer(layers.LayerTypeDNS) != nil
}

// ---------------------------------------------------------------------------
// NDR-computed enrichment functions (exported for detection engine use)
// ---------------------------------------------------------------------------

// ShannonEntropy computes the Shannon entropy of a string in bits per
// character. High entropy (> 3.5) in a DNS query name suggests encoded
// or encrypted data, which is a strong indicator of DNS tunneling.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return math.Round(entropy*10000) / 10000 // 4 decimal places
}

// SubdomainDepth counts the number of labels (dot-separated parts) in a
// domain name. "a.b.c.example.com" has depth 5. Deep subdomains (> 3-4
// levels) combined with high entropy suggest DNS tunneling.
func SubdomainDepth(domain string) int {
	if domain == "" {
		return 0
	}
	// Remove trailing dot if present.
	domain = strings.TrimSuffix(domain, ".")
	return len(strings.Split(domain, "."))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func qtypeToName(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeTXT:
		return "TXT"
	default:
		return strings.TrimPrefix(layers.DNSType(t).String(), "DNSType")
	}
}

func qclassToName(c layers.DNSClass) string {
	switch c {
	case layers.DNSClassIN:
		return "IN"
	case layers.DNSClassCS:
		return "CS"
	case layers.DNSClassCH:
		return "CH"
	case layers.DNSClassHS:
		return "HS"
	case layers.DNSClassAny:
		return "ANY"
	default:
		return "unknown"
	}
}

func rcodeToName(r layers.DNSResponseCode) string {
	switch r {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	default:
		return "unknown"
	}
}
