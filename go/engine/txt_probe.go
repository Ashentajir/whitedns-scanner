package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DnsProbeTXT executes TXT lookups against a resolver across the configured
// protocols. It mirrors the A-record path but does not compare answers against
// the truth table.
func DnsProbeTXT(ctx context.Context, resolverIP string, domain string, timeout time.Duration, dialer *net.Dialer, dohClient *http.Client, customPorts []int) []DnsProbeResult {
	results := make([]DnsProbeResult, 0, 8)
	queryName := buildTxtQueryName(domain)

	if len(customPorts) > 0 {
		for _, port := range customPorts {
			results = append(results, DnsProbeTXTUDPWithDialer(ctx, resolverIP, queryName, timeout, dialer, port))
			results = append(results, DnsProbeTXTTCPWithDialer(ctx, resolverIP, queryName, timeout, dialer, port))
			if port == 853 {
				results = append(results, DnsProbeTXTDoTWithDialer(ctx, resolverIP, queryName, timeout, dialer, port))
			}
			if port == 443 {
				results = append(results, DnsProbeTXTDoHWithClient(ctx, resolverIP, queryName, timeout, dohClient, port))
			}
		}
		return results
	}

	results = append(results, DnsProbeTXTUDPWithDialer(ctx, resolverIP, queryName, timeout, dialer, 53))
	results = append(results, DnsProbeTXTTCPWithDialer(ctx, resolverIP, queryName, timeout, dialer, 53))
	results = append(results, DnsProbeTXTDoTWithDialer(ctx, resolverIP, queryName, timeout, dialer, 853))
	results = append(results, DnsProbeTXTDoHWithClient(ctx, resolverIP, queryName, timeout, dohClient, 443))
	return results
}

// DnsProbeTXTUDPWithDialer sends a TXT query over UDP.
func DnsProbeTXTUDPWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}
	query, _ := buildDnsQuery(queryName, 16)

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
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "UDP_READ: " + truncErr(err)
		return result
	}

	txts, err := parseDnsResponse(buf[:n], 16)
	if err != nil {
		result.Error = "UDP_PARSE: " + err.Error()
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	return result
}

// DnsProbeTXTTCPWithDialer sends a TXT query over TCP.
func DnsProbeTXTTCPWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}
	query, _ := buildDnsQuery(queryName, 16)

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

	txts, err := parseDnsResponse(respBuf, 16)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	return result
}

// DnsProbeTXTDoTWithDialer sends a TXT query over DNS-over-TLS.
func DnsProbeTXTDoTWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}
	query, _ := buildDnsQuery(queryName, 16)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}

	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
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

	txts, err := parseDnsResponse(respBuf, 16)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	return result
}

// DnsProbeTXTDoHWithClient sends a TXT query over DNS-over-HTTPS.
func DnsProbeTXTDoHWithClient(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, client *http.Client, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoH/%d", port)}
	url := fmt.Sprintf("https://%s:%d/dns-query?name=%s&type=TXT", resolverIP, port, queryName)

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

	var txts []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 16 {
			txts = append(txts, ans.Data)
		}
	}
	if len(txts) == 0 {
		result.Error = "DoH_NO_TXT"
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	return result
}
