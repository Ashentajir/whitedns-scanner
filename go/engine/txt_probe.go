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
	"strings"
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

	hdr, txts, edns, ttfb, err := probeUDPWithFallback(ctx, resolverIP, queryName, 16, timeout, dialer, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "UDP: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}

// DnsProbeTXTTCPWithDialer sends a TXT query over TCP.
func DnsProbeTXTTCPWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}
	query, txid := buildDnsQuery(queryName, 16, true)

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

	hdr, txts, edns, err := parseDnsMessage(respBuf, 16, txid, true)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	return result
}

// DnsProbeTXTDoTWithDialer sends a TXT query over DNS-over-TLS.
func DnsProbeTXTDoTWithDialer(ctx context.Context, resolverIP string, queryName string, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}
	query, txid := buildDnsQuery(queryName, 16, true)

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
	respBuf, err := readTCPResponse(tlsConn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "DoT_READ: " + truncErr(err)
		return result
	}

	hdr, txts, edns, err := parseDnsMessage(respBuf, 16, txid, true)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
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
			// DoH JSON wraps TXT strings in quotes; strip them for parity with
			// the wire probes so passthrough comparisons line up.
			txts = append(txts, strings.Trim(ans.Data, "\""))
		}
	}
	if len(txts) == 0 {
		result.Error = "DoH_NO_TXT"
		return result
	}

	result.Responded = true
	result.AnswerTXT = txts
	result.Header, result.HeaderOK = dohHeader(dohResp), true
	return result
}
