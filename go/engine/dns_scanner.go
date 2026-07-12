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

	// Header holds the parsed DNS response header (all flags + section counts).
	// HeaderOK reports whether the header was successfully parsed.
	Header   DnsHeader
	HeaderOK bool
	// EDNS is true when the resolver echoed an EDNS0 OPT record, signalling it
	// accepts large UDP payloads — a prerequisite for high-bandwidth tunneling.
	EDNS bool
}

// DnsHeader is the fully-decoded 12-byte DNS message header (RFC 1035 §4.1.1).
// Exposed so callers can inspect every flag — not just the answer records —
// which is what the "full header dump" output and tunnel classifier rely on.
type DnsHeader struct {
	ID      uint16 // Transaction ID
	QR      bool   // Query (false) / Response (true)
	Opcode  uint8  // 0=QUERY, 1=IQUERY, 2=STATUS
	AA      bool   // Authoritative Answer
	TC      bool   // TrunCation — answer did not fit, retry over TCP
	RD      bool   // Recursion Desired (what we asked for)
	RA      bool   // Recursion Available — resolver is an open recursor
	Z       uint8  // Reserved (3 bits)
	Rcode   uint8  // Response code (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED)
	QDCount uint16 // Questions
	ANCount uint16 // Answer records
	NSCount uint16 // Authority records
	ARCount uint16 // Additional records
}

// parseDnsHeader decodes the fixed 12-byte header at the start of a DNS message.
func parseDnsHeader(packet []byte) (DnsHeader, error) {
	if len(packet) < 12 {
		return DnsHeader{}, fmt.Errorf("packet too short for header: %d bytes", len(packet))
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	return DnsHeader{
		ID:      binary.BigEndian.Uint16(packet[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0F),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		Z:       uint8((flags >> 4) & 0x07),
		Rcode:   uint8(flags & 0x0F),
		QDCount: binary.BigEndian.Uint16(packet[4:6]),
		ANCount: binary.BigEndian.Uint16(packet[6:8]),
		NSCount: binary.BigEndian.Uint16(packet[8:10]),
		ARCount: binary.BigEndian.Uint16(packet[10:12]),
	}, nil
}

// String renders the header as a compact single-line dump for reports, e.g.
// "id=0x1a2b QR AA=0 TC=0 RD RA rcode=0 qd=1 an=2 ns=0 ar=1".
func (h DnsHeader) String() string {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("id=0x%04x qr=%d op=%d aa=%d tc=%d rd=%d ra=%d z=%d rcode=%d qd=%d an=%d ns=%d ar=%d",
		h.ID, b(h.QR), h.Opcode, b(h.AA), b(h.TC), b(h.RD), b(h.RA), h.Z, h.Rcode,
		h.QDCount, h.ANCount, h.NSCount, h.ARCount)
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
	Status int  `json:"Status"`
	TC     bool `json:"TC"` // Truncated
	RD     bool `json:"RD"` // Recursion Desired
	RA     bool `json:"RA"` // Recursion Available — open recursor
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

// ednsUDPPayloadSize is the advertised EDNS0 receive-buffer size. 4096 lets the
// resolver return large answers in a single UDP datagram — both a robustness win
// (fewer truncations) and the signal we use to gauge tunnel bandwidth.
const ednsUDPPayloadSize = 4096

// buildDnsQuery constructs a raw DNS query for the given domain and record type.
// Returns the wire-format bytes and the randomized transaction ID.
// Uses crypto/rand for TXID to evade pattern-based DPI blocking AND to let the
// caller validate that a response is genuinely ours (anti-spoofing). When edns
// is true an EDNS0 OPT record is added so we can detect large-payload support.
func buildDnsQuery(domain string, qtype uint16, edns bool) ([]byte, uint16) {
	// Generate cryptographically random transaction ID
	var txidBytes [2]byte
	_, _ = rand.Read(txidBytes[:])
	txid := binary.BigEndian.Uint16(txidBytes[:])

	arCount := byte(0x00)
	if edns {
		arCount = 0x01
	}

	// DNS Header (12 bytes)
	// Flags: 0x0100 = standard query, recursion desired (RD=1)
	header := []byte{
		txidBytes[0], txidBytes[1], // Transaction ID
		0x01, 0x00, // Flags: Standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, arCount, // ARCOUNT: 1 if EDNS OPT appended, else 0
	}

	// DNS Question section — encode domain as labels
	question := encodeDomainName(domain)

	// QTYPE, QCLASS: IN (1)
	question = append(question, byte(qtype>>8), byte(qtype))
	question = append(question, 0x00, 0x01) // Class IN

	packet := append(header, question...)

	if edns {
		packet = append(packet, encodeEDNSOpt()...)
	}
	return packet, txid
}

// encodeEDNSOpt builds a minimal EDNS0 OPT pseudo-record (RFC 6891) for the
// additional section: root name, TYPE=OPT(41), CLASS=UDP payload size, zeroed
// extended-rcode/flags/version, and empty RDATA.
func encodeEDNSOpt() []byte {
	return []byte{
		0x00,                                             // Root domain name
		0x00, 0x29,                                       // TYPE: OPT (41)
		byte(ednsUDPPayloadSize >> 8), byte(ednsUDPPayloadSize & 0xFF), // CLASS: UDP payload size
		0x00,       // Extended RCODE
		0x00,       // EDNS version 0
		0x00, 0x00, // Z flags
		0x00, 0x00, // RDLENGTH: 0
	}
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

// parseDnsMessage decodes a full DNS response: header, answer records of the
// requested type, and whether an EDNS0 OPT record is present anywhere in the
// message. It handles name-pointer compression and is bounds-checked throughout.
//
// When checkTxid is set the response ID must equal wantTxid, and the QR bit must
// be set — this rejects blindly-spoofed / off-path injected packets that a
// poisoning-detection scanner must not treat as genuine answers.
func parseDnsMessage(packet []byte, qtype uint16, wantTxid uint16, checkTxid bool) (DnsHeader, []string, bool, error) {
	hdr, err := parseDnsHeader(packet)
	if err != nil {
		return DnsHeader{}, nil, false, err
	}

	if checkTxid && hdr.ID != wantTxid {
		return hdr, nil, false, fmt.Errorf("txid mismatch got=0x%04x want=0x%04x", hdr.ID, wantTxid)
	}
	if !hdr.QR {
		return hdr, nil, false, fmt.Errorf("not a response (QR=0)")
	}
	if hdr.Rcode != 0 {
		return hdr, nil, false, fmt.Errorf("dns error rcode=%d", hdr.Rcode)
	}

	offset := 12

	// Skip the question section.
	for i := 0; i < int(hdr.QDCount); i++ {
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+4 > len(packet) {
			return hdr, nil, false, fmt.Errorf("malformed question section")
		}
		offset += 4 // QTYPE (2) + QCLASS (2)
	}

	// Walk every resource record (answer + authority + additional). We collect
	// matching records from the answer section and note any OPT record (EDNS0)
	// regardless of section.
	var answers []string
	edns := false
	total := int(hdr.ANCount) + int(hdr.NSCount) + int(hdr.ARCount)
	inAnswer := int(hdr.ANCount)

	for i := 0; i < total; i++ {
		if offset >= len(packet) {
			break
		}
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+10 > len(packet) {
			break
		}

		rType := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2 // TYPE
		offset += 2 // CLASS (OPT: UDP payload size — ignored here)
		offset += 4 // TTL  (OPT: extended rcode/flags — ignored here)
		rdLength := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
		offset += 2

		if offset+rdLength > len(packet) {
			break
		}

		if rType == 41 { // OPT pseudo-record => resolver understood our EDNS0 query
			edns = true
		}

		if i < inAnswer && rType == qtype {
			switch qtype {
			case 1:
				if rdLength == 4 {
					answers = append(answers, fmt.Sprintf("%d.%d.%d.%d",
						packet[offset], packet[offset+1],
						packet[offset+2], packet[offset+3]))
				}
			case 16:
				if txt, err := parseTxtRData(packet[offset : offset+rdLength]); err == nil && txt != "" {
					answers = append(answers, txt)
				}
			}
		}

		offset += rdLength
	}

	if len(answers) == 0 {
		return hdr, nil, edns, fmt.Errorf("no %s records in response", dnsQueryTypeName(qtype))
	}

	return hdr, answers, edns, nil
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

// DnsProbeUDPWithDialer sends a DNS A query over UDP on the specified port.
func DnsProbeUDPWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}

	hdr, ips, edns, ttfb, err := probeUDPWithFallback(ctx, resolverIP, domain, 1, timeout, dialer, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "UDP: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// probeUDPWithFallback dials the resolver and sends an EDNS0 query, then — if
// that gets no usable answer — retries once with a bare (non-EDNS) query on the
// same socket. This defeats censoring middleboxes that silently drop or FORMERR
// EDNS traffic, so poisoned/broken resolvers are still observed rather than
// timing out. Returns the response header, answers, whether EDNS0 is usable, the
// time-to-first-byte, and an error if both attempts fail.
func probeUDPWithFallback(ctx context.Context, resolverIP string, name string, qtype uint16, timeout time.Duration, dialer *net.Dialer, port int) (DnsHeader, []string, bool, time.Duration, error) {
	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return DnsHeader{}, nil, false, 0, fmt.Errorf("DIAL: %s", truncErr(err))
	}
	defer conn.Close()

	var (
		hdr     DnsHeader
		ttfb    time.Duration
		lastErr error
	)
	// EDNS0 first (large-payload detection); bare query second (compatibility).
	for i, useEDNS := range []bool{true, false} {
		query, txid := buildDnsQuery(name, qtype, useEDNS)
		conn.SetDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(query); werr != nil {
			lastErr = fmt.Errorf("WRITE: %s", truncErr(werr))
			continue
		}
		start := time.Now()
		h, answers, edns, perr := readUDPResponse(conn, txid, qtype)
		attemptTTFB := time.Since(start)
		if i == 0 || ttfb == 0 {
			ttfb = attemptTTFB
		}
		if perr == nil {
			return h, answers, edns, attemptTTFB, nil
		}
		hdr, lastErr = h, fmt.Errorf("PARSE: %s", perr.Error())
	}
	return hdr, nil, false, ttfb, lastErr
}

// readUDPResponse reads datagrams until one is a genuine response to our query
// (matching TXID + QR set) or the connection deadline fires. Datagrams whose
// TXID does not match ours are off-path spoofs / stragglers and are skipped —
// this is the core anti-injection guard for hostile networks.
func readUDPResponse(conn net.Conn, txid uint16, qtype uint16) (DnsHeader, []string, bool, error) {
	buf := make([]byte, ednsUDPPayloadSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return DnsHeader{}, nil, false, err
		}
		hdr, answers, edns, perr := parseDnsMessage(buf[:n], qtype, txid, true)
		if perr != nil && strings.Contains(perr.Error(), "txid mismatch") {
			continue // not our answer — keep waiting for the real one
		}
		return hdr, answers, edns, perr
	}
}

// DnsProbeTCP sends a DNS query over TCP/53.
// TCP DNS uses a 2-byte length prefix before the query packet.
// Often overlooked by DPI systems that only inspect UDP/53.
// DnsProbeTCPWithDialer sends a TCP-wrapped DNS query on the specified port.
func DnsProbeTCPWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}

	query, txid := buildDnsQuery(domain, 1, true)

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
	respBuf, err := readTCPResponse(conn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "TCP_READ: " + truncErr(err)
		return result
	}

	hdr, ips, edns, err := parseDnsMessage(respBuf, 1, txid, true)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// readTCPResponse reads one length-prefixed DNS message from a stream
// (TCP/53 or a DoT tunnel). The 2-byte big-endian prefix bounds the body.
func readTCPResponse(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 || respLen > ednsUDPPayloadSize {
		return nil, fmt.Errorf("bad length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}
	return respBuf, nil
}

// DnsProbeDoT sends a DNS query over DNS-over-TLS (port 853).
// The wire format is identical to TCP DNS, but wrapped in a TLS tunnel.
// DnsProbeDoTWithDialer performs DNS-over-TLS against the resolver on the given port.
func DnsProbeDoTWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}

	query, txid := buildDnsQuery(domain, 1, true)

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
	respBuf, err := readTCPResponse(tlsConn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "DoT_READ: " + truncErr(err)
		return result
	}

	hdr, ips, edns, err := parseDnsMessage(respBuf, 1, txid, true)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
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
	result.Header, result.HeaderOK = dohHeader(dohResp), true
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// dohHeader synthesizes a DnsHeader from the flags exposed by the DoH JSON API.
// The JSON format carries QR implicitly (it's always a response) plus TC/RD/RA
// and Status (rcode); the wire-only fields (ID, AA, counts) are left zero.
func dohHeader(r dohJSONResponse) DnsHeader {
	return DnsHeader{QR: true, TC: r.TC, RD: r.RD, RA: r.RA, Rcode: uint8(r.Status)}
}

// truncErr truncates an error message to keep logs clean.
func truncErr(err error) string {
	s := err.Error()
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
