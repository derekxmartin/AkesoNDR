// Package http implements the AkesoNDR HTTP protocol dissector.
//
// It parses HTTP request/response pairs from reassembled TCP stream data,
// extracting all metadata fields defined in REQUIREMENTS.md Section 4.2.
// The parser operates on raw byte slices (not live packets) because HTTP
// data arrives via the TCP reassembly engine as complete stream buffers.
package http

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/akesondr/akeso-ndr/internal/common"
)

const (
	// maxURILen is the maximum URI length stored (truncated per spec).
	maxURILen = 512
	// maxUALen is the maximum User-Agent length stored.
	maxUALen = 512
)

// Parser extracts HTTP metadata from reassembled TCP streams.
type Parser struct{}

// NewParser creates an HTTP parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts HTTPMeta from reassembled client (request) and server
// (response) stream data. Returns nil if the data does not look like HTTP.
func (p *Parser) Parse(client, server []byte) *common.HTTPMeta {
	if len(client) == 0 {
		return nil
	}

	// Try to parse an HTTP request from the client data.
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(client)))
	if err != nil {
		return nil
	}
	defer req.Body.Close()

	meta := &common.HTTPMeta{
		Method: req.Method,
		URI:    truncate(req.RequestURI, maxURILen),
		Host:   req.Host,
	}

	// Headers.
	if ua := req.Header.Get("User-Agent"); ua != "" {
		meta.UserAgent = truncate(ua, maxUALen)
	}
	if ref := req.Header.Get("Referer"); ref != "" {
		meta.Referrer = ref
	}
	if ae := req.Header.Get("Accept-Encoding"); ae != "" {
		meta.AcceptEncoding = ae
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		meta.OrigMIMETypes = ct
	}

	// Cookie variable names (values stripped for privacy).
	for _, cookie := range req.Cookies() {
		meta.CookieVars = append(meta.CookieVars, cookie.Name)
	}

	// Request body length.
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		meta.RequestBodyLen = int64(len(body))
	}

	// Try to parse an HTTP response from the server data.
	if len(server) > 0 {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(server)), req)
		if err == nil {
			defer resp.Body.Close()

			meta.StatusCode = resp.StatusCode
			meta.StatusMsg = resp.Status

			if ct := resp.Header.Get("Content-Type"); ct != "" {
				meta.RespMIMETypes = ct
			}

			// Response body length.
			if resp.Body != nil {
				body, _ := io.ReadAll(resp.Body)
				meta.ResponseBodyLen = int64(len(body))
			}
		}
	}

	return meta
}

// CanParse returns true if the client data starts with an HTTP method,
// indicating this is likely an HTTP stream.
func (p *Parser) CanParse(client []byte) bool {
	if len(client) == 0 {
		return false
	}
	// Check for common HTTP method prefixes.
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	upper := strings.ToUpper(string(client[:min(10, len(client))]))
	for _, m := range methods {
		if strings.HasPrefix(upper, m) {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
