package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════════════════════
// DNS DISCOVERY ENGINE — High-Precision Resolver Scanner
//
// Designed for hostile network environments with active DNS poisoning.
// Probes resolvers across 4 protocols and validates answer integrity
// against a "Truth Table" fetched from trusted DoH providers.
// ════════════════════════════════════════════════════════════════════════════════

// DnsProbeResult holds the outcome of a single DNS protocol probe against one resolver.
type DnsProbeResult struct {
	Protocol   string        // "UDP", "TCP", "DoT", "DoH"
	Responded  bool          // Did we get a parseable DNS response?
	IsPoisoned bool          // Did the answer IPs mismatch the truth table?
	AnswerIPs  []string      // A-record IPs extracted from the response
	AnswerTXT  []string      // TXT strings extracted from the response
	TTFB       time.Duration // Time to first byte of the DNS response
	Error      string        // Human-readable error, empty on success
}

// ════════════════════════════════════════════════════════════════════════════════
// TRUTH TABLE — The "Ground Truth" for Integrity Verification
// ════════════════════════════════════════════════════════════════════════════════

// trustedDoHProvider defines a DoH endpoint for fetching the truth table.
type trustedDoHProvider struct {
	Name string
	URL  string // Full URL template; %s is replaced with the domain
}

// trustedProviders is the ordered fallback list of DoH providers.
// Cloudflare first, then Google, then Quad9.
var trustedProviders = []trustedDoHProvider{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query?name=%s&type=A"},
	{Name: "Google", URL: "https://dns.google/dns-query?name=%s&type=A"},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query?name=%s&type=A"},
}

// dohJSONResponse models the JSON wire format returned by DoH providers
// when queried with Accept: application/dns-json.
type dohJSONResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// TruthTable holds the verified "correct" IPs for a target domain.
// Used to detect DNS poisoning: if a resolver returns IPs not in this set,
// the resolver is marked as POISONED.
type TruthTable struct {
	Domain   string
	TruthIPs map[string]bool // Set of known-correct A-record IPs
	mu       sync.RWMutex
	Provider string // Which DoH provider succeeded
}

// NewTruthTable creates an empty truth table for a given domain.
func NewTruthTable(domain string) *TruthTable {
	return &TruthTable{
		Domain:   domain,
		TruthIPs: make(map[string]bool),
	}
}

// FetchTruth populates the truth table by querying trusted DoH providers.
// Tries each provider in order; stops on first success.
// Falls back to hardcoded well-known IPs if all providers fail.
func (t *TruthTable) FetchTruth() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}

	for _, provider := range trustedProviders {
		url := fmt.Sprintf(provider.URL, t.Domain)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		var dohResp dohJSONResponse
		if err := json.Unmarshal(body, &dohResp); err != nil {
			continue
		}

		if dohResp.Status != 0 {
			continue
		}

		for _, ans := range dohResp.Answer {
			if ans.Type == 1 { // A record
				ip := strings.TrimSpace(ans.Data)
				if net.ParseIP(ip) != nil {
					t.TruthIPs[ip] = true
				}
			}
		}

		if len(t.TruthIPs) > 0 {
			t.Provider = provider.Name
			return nil
		}
	}

	// ── Hardcoded fallback for well-known domains ──
	// If all DoH providers are blocked (deep censorship), use known IPs
	// so the scanner can still detect obvious poisoning.
	fallbacks := map[string][]string{
		"google.com":    {"142.250.80.46", "142.250.80.78", "142.250.80.110"},
		"speedtest.net": {"151.139.72.2"},
		"facebook.com":  {"157.240.1.35", "157.240.3.35"},
	}

	if ips, ok := fallbacks[t.Domain]; ok {
		for _, ip := range ips {
			t.TruthIPs[ip] = true
		}
		t.Provider = "Hardcoded Fallback"
		return nil
	}

	return fmt.Errorf("truth table: all DoH providers failed and no hardcoded fallback for %q", t.Domain)
}

// Verify checks if any of the given IPs match the truth table.
// Returns true if at least one IP is in the trusted set (clean).
// Returns false (poisoned) if none match.
func (t *TruthTable) Verify(ips []string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.TruthIPs) == 0 {
		// If we have no truth data, we can't verify — assume clean
		return true
	}

	for _, ip := range ips {
		if t.TruthIPs[ip] {
			return true
		}
	}
	return false
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS WIRE PROTOCOL — Manual Packet Construction (No External Dependencies)
// ════════════════════════════════════════════════════════════════════════════════

// buildDnsQuery constructs a raw DNS A-record query for the given domain.
// Returns the wire-format bytes and the randomized transaction ID.
// Uses crypto/rand for TXID to evade pattern-based DPI blocking.
func buildDnsQuery(domain string, qtype uint16) ([]byte, uint16) {
	// Generate cryptographically random transaction ID
	var txidBytes [2]byte
	_, _ = rand.Read(txidBytes[:])
	txid := binary.BigEndian.Uint16(txidBytes[:])

	// DNS Header (12 bytes)
	// Flags: 0x0100 = standard query, recursion desired (RD=1)
	header := []byte{
		txidBytes[0], txidBytes[1], // Transaction ID
		0x01, 0x00, // Flags: Standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// DNS Question section — encode domain as labels
	question := encodeDomainName(domain)

	// QTYPE: A (1), QCLASS: IN (1)
	question = append(question, byte(qtype>>8), byte(qtype))
	question = append(question, 0x00, 0x01) // Class IN

	packet := append(header, question...)
	return packet, txid
}

// encodeDomainName converts "google.com" into DNS wire format:
// [6]google[3]com[0]
func encodeDomainName(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // Root label terminator
	return buf
}

// parseDnsResponse extracts A-record IPs from a raw DNS response packet.
// Handles pointer compression in the answer section.
func parseDnsResponse(packet []byte, qtype uint16) ([]string, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(packet))
	}

	// Check RCODE in flags (lower 4 bits of byte 3)
	rcode := packet[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns error rcode=%d", rcode)
	}

	anCount := binary.BigEndian.Uint16(packet[6:8])
	if anCount == 0 {
		return nil, fmt.Errorf("no answer records")
	}

	// Skip header (12 bytes) and question section
	offset := 12

	// Skip question section: read QDCOUNT questions
	qdCount := binary.BigEndian.Uint16(packet[4:6])
	for i := 0; i < int(qdCount); i++ {
		// Skip domain name
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+4 > len(packet) {
			return nil, fmt.Errorf("malformed question section")
		}
		offset += 4 // Skip QTYPE (2) + QCLASS (2)
	}

	// Parse answer section
	var ips []string
	for i := 0; i < int(anCount); i++ {
		if offset >= len(packet) {
			break
		}

		// Skip answer name (could be a pointer)
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+10 > len(packet) {
			break
		}

		aType := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2 // TYPE
		offset += 2 // CLASS
		offset += 4 // TTL
		rdLength := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2

		if offset+int(rdLength) > len(packet) {
			break
		}

		if aType == qtype {
			switch qtype {
			case 1:
				if rdLength == 4 {
					ip := fmt.Sprintf("%d.%d.%d.%d",
						packet[offset], packet[offset+1],
						packet[offset+2], packet[offset+3])
					ips = append(ips, ip)
				}
			case 16:
				if txt, err := parseTxtRData(packet[offset : offset+int(rdLength)]); err == nil && txt != "" {
					ips = append(ips, txt)
				}
			}
		}

		offset += int(rdLength)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no %s records in response", dnsQueryTypeName(qtype))
	}

	return ips, nil
}

func parseTxtRData(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("empty TXT record")
	}

	parts := make([]string, 0, 4)
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			return "", fmt.Errorf("malformed TXT record")
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, ""), nil
}

func dnsQueryTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 16:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE_%d", qtype)
	}
}

// skipDnsName advances past a DNS domain name at the given offset,
// handling both label sequences and pointer compression (0xC0 prefix).
func skipDnsName(packet []byte, offset int) int {
	if offset >= len(packet) {
		return -1
	}

	for {
		if offset >= len(packet) {
			return -1
		}

		length := int(packet[offset])

		// Pointer (top 2 bits are 11)
		if length&0xC0 == 0xC0 {
			return offset + 2 // Pointer is 2 bytes, done
		}

		// Root label — end of name
		if length == 0 {
			return offset + 1
		}

		// Regular label
		offset += 1 + length
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// PROTOCOL PROBES — UDP / TCP / DoT / DoH
//
// Each probe:
//   1. Builds a DNS query with randomized TXID
//   2. Connects to the resolver on the protocol-specific port
//   3. Measures TTFB (Time to First Byte)
//   4. Parses the response and validates against the truth table
// ════════════════════════════════════════════════════════════════════════════════

// DnsProbeUDPWithDialer sends a plain DNS query over UDP on the specified port.
func DnsProbeUDPWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}

	query, _ := buildDnsQuery(domain, 1)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		result.Error = "UDP_DIAL: " + truncErr(err)
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		result.Error = "UDP_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "UDP_READ: " + truncErr(err)
		return result
	}

	ips, err := parseDnsResponse(buf[:n], 1)
	if err != nil {
		result.Error = "UDP_PARSE: " + err.Error()
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// DnsProbeTCP sends a DNS query over TCP/53.
// TCP DNS uses a 2-byte length prefix before the query packet.
// Often overlooked by DPI systems that only inspect UDP/53.
// DnsProbeTCPWithDialer sends a TCP-wrapped DNS query on the specified port.
func DnsProbeTCPWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}

	query, _ := buildDnsQuery(domain, 1)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = "TCP_DIAL: " + truncErr(err)
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := conn.Write(tcpMsg); err != nil {
		result.Error = "TCP_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		result.Error = "TCP_READ_LEN: " + truncErr(err)
		return result
	}
	result.TTFB = time.Since(start)

	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 || respLen > 4096 {
		result.Error = fmt.Sprintf("TCP_BAD_LEN: %d", respLen)
		return result
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		result.Error = "TCP_READ_BODY: " + truncErr(err)
		return result
	}

	ips, err := parseDnsResponse(respBuf, 1)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// DnsProbeDoT sends a DNS query over DNS-over-TLS (port 853).
// The wire format is identical to TCP DNS, but wrapped in a TLS tunnel.
// DnsProbeDoTWithDialer performs DNS-over-TLS against the resolver on the given port.
func DnsProbeDoTWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}

	query, _ := buildDnsQuery(domain, 1)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}

	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		result.Error = "DoT_TLS: " + truncErr(err)
		return result
	}
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(timeout))

	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := tlsConn.Write(tcpMsg); err != nil {
		result.Error = "DoT_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	var lenBuf [2]byte
	if _, err := io.ReadFull(tlsConn, lenBuf[:]); err != nil {
		result.Error = "DoT_READ_LEN: " + truncErr(err)
		return result
	}
	result.TTFB = time.Since(start)

	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 || respLen > 4096 {
		result.Error = fmt.Sprintf("DoT_BAD_LEN: %d", respLen)
		return result
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(tlsConn, respBuf); err != nil {
		result.Error = "DoT_READ_BODY: " + truncErr(err)
		return result
	}

	ips, err := parseDnsResponse(respBuf, 1)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// DnsProbeDoH sends a DNS query via DNS-over-HTTPS (port 443).
// Uses the JSON API format (application/dns-json) for simplicity.
// DnsProbeDoHWithClient sends a DNS-over-HTTPS query using a shared HTTP client.
func DnsProbeDoHWithClient(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, client *http.Client, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoH/%d", port)}

	url := fmt.Sprintf("https://%s:%d/dns-query?name=%s&type=A", resolverIP, port, domain)

	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = "DoH_REQ: " + truncErr(err)
		return result
	}
	req.Header.Set("Accept", "application/dns-json")

	start := time.Now()
	resp, err := client.Do(req)
	result.TTFB = time.Since(start)

	if err != nil {
		result.Error = "DoH_HTTP: " + truncErr(err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("DoH_STATUS: %d", resp.StatusCode)
		return result
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		result.Error = "DoH_READ: " + truncErr(err)
		return result
	}

	var dohResp dohJSONResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		result.Error = "DoH_JSON: " + truncErr(err)
		return result
	}

	if dohResp.Status != 0 {
		result.Error = fmt.Sprintf("DoH_RCODE: %d", dohResp.Status)
		return result
	}

	var ips []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 1 {
			ip := strings.TrimSpace(ans.Data)
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
	}

	if len(ips) == 0 {
		result.Error = "DoH_NO_A"
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// truncErr truncates an error message to keep logs clean.
func truncErr(err error) string {
	s := err.Error()
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
