package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// scanWorker processes targets from the jobs channel.
// Each worker owns its own http.Client with an anti-crash transport.
func (e *Engine) scanWorker(ctx context.Context, jobs <-chan Target, results chan<- ScanResult) {
	defer e.wg.Done()

	timeout := time.Duration(e.config.TimeoutSecs) * time.Second

	// Use shared client initialized on the Engine to allow scaling to very high concurrency.
	// Fall back to creating a local client if for some reason it's missing.
	client := e.httpClient
	if client == nil {
		transport := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
			MaxIdleConns:        1000,
			MaxConnsPerHost:     100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: timeout / 2,
			ForceAttemptHTTP2:   false,
		}
		client = &http.Client{Transport: transport, Timeout: timeout}
		defer transport.CloseIdleConnections()
	}

	layerTimeout := timeout / 2
	if layerTimeout < 3*time.Second {
		layerTimeout = 3 * time.Second
	}

	for target := range jobs {
		// Respect PAUSED or STOPPED
		if !e.checkStateOrWait(ctx) {
			results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
			continue
		}

		start := time.Now()

		host := target.Host
		port := target.Port
		scheme := target.Scheme

		// ── Layer 1-3: DNS + TCP + TLS via probe.go ──
		probeResult := PreFlightLayerCheck(ctx, host, port, scheme, layerTimeout, e.config.SpoofedSNI)

		// Handle fatal OS-level errors (EMFILE) gracefully
		if probeResult.Status == "FATAL_ERR" {
			results <- ScanResult{
				Label:      target.Label,
				URL:        target.URL,
				ResolvedIP: probeResult.ResolvedIP,
				Port:       port,
				LatencyMs:  int(time.Since(start).Milliseconds()),
				Error:      "FATAL_ERR",
			}
			// Brief backoff to let the OS reclaim sockets
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// ── HTTPS → HTTP Fallback (Anti-Censorship / DPI bypass) ──
		if probeResult.Status != "PASSED" {
			fallbackScheme := "http"
			if scheme == "http" {
				fallbackScheme = "https"
			}

			fallbackResult := PreFlightLayerCheck(ctx, host, port, fallbackScheme, layerTimeout, "")
			if fallbackResult.Status == "PASSED" {
				scheme = fallbackScheme
				probeResult = fallbackResult
			} else {
				results <- ScanResult{
					Label:      target.Label,
					URL:        target.URL,
					ResolvedIP: probeResult.ResolvedIP,
					Port:       port,
					LatencyMs:  int(time.Since(start).Milliseconds()),
					Error:      fallbackResult.Status,
				}
				continue
			}
		}

		resolvedIP := probeResult.ResolvedIP

		// ──────────────────────────────────────────────
		// Layer 4: HTTP GET — dial RESOLVED IP with spoofed Host header
		// ──────────────────────────────────────────────
		// Build the URL using the resolved IP instead of domain.
		// This forces the connection to go directly to the IP,
		// bypassing any DNS-level blocking.
		httpURL := fmt.Sprintf("%s://%s:%d/", scheme, resolvedIP, port)

		var lastErr string
		var finalStatus int
		success := false

		for attempt := 0; attempt <= e.config.RetryCount; attempt++ {
			if !e.checkStateOrWait(ctx) {
				results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
				success = true
				break
			}

			req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
			if err != nil {
				lastErr = "HTTP_REQ_ERR"
				break
			}

			// Spoof the Host header to the original domain.
			// This is critical: the IP is dialed but the server
			// sees the correct virtual host.
			req.Host = host
			req.Header.Set("Host", host)
			req.Header.Set("User-Agent", e.config.UserAgent)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "close")

			resp, err := client.Do(req)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					lastErr = "ABORTED"
					break
				}

				// Check for fatal socket exhaustion
				if isSocketExhaustion(err) {
					lastErr = "FATAL_ERR"
					time.Sleep(500 * time.Millisecond)
					break
				}

				if strings.Contains(err.Error(), "timeout") {
					lastErr = "HTTP_TIMEOUT"
					time.Sleep(300 * time.Millisecond)
					continue
				}
				errStr := err.Error()
				if len(errStr) > 30 {
					errStr = errStr[:30]
				}
				lastErr = "HTTP_ERR: " + errStr
				break
			}

			finalStatus = resp.StatusCode
			resp.Body.Close()
			success = true
			results <- ScanResult{
				Label:      target.Label,
				URL:        fmt.Sprintf("%s://%s:%d", scheme, host, port),
				ResolvedIP: resolvedIP,
				Port:       port,
				Status:     finalStatus,
				LatencyMs:  int(time.Since(start).Milliseconds()),
			}
			break
		}

		if !success {
			if lastErr == "" {
				lastErr = "UNKNOWN"
			}
			results <- ScanResult{
				Label:      target.Label,
				URL:        target.URL,
				ResolvedIP: resolvedIP,
				Port:       port,
				LatencyMs:  int(time.Since(start).Milliseconds()),
				Error:      lastErr,
			}
		}
	}
}

// checkStateOrWait blocks if PAUSED, returns false if STOPPED/Context Done, true if RUNNING.
func (e *Engine) checkStateOrWait(ctx context.Context) bool {
	for {
		e.mu.Lock()
		state := e.state
		e.mu.Unlock()

		if state == "STOPPED" {
			return false
		}
		if state == "RUNNING" {
			return true
		}

		// PAUSED - Wait for signal or context cancellation
		select {
		case <-ctx.Done():
			return false
		case <-e.resumeChan:
			// Woke up, loop again to check state
		}
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS DISCOVERY WORKER
//
// Processes resolver IPs from the jobs channel, probes each across all 4
// DNS protocols (UDP/TCP/DoT/DoH), and emits one ScanResult per protocol.
// ════════════════════════════════════════════════════════════════════════════════

// classifyTunnel decides whether a resolver probe is suitable for DNS tunneling
// per the criteria: open recursion (RA=1) + EDNS0 large-payload support + TXT
// passthrough. Poisoning is intentionally NOT a disqualifier — a poisoning
// resolver can still carry a tunnel — it is reported separately. The returned
// reason lists what is missing so the report explains each verdict.
func classifyTunnel(pr DnsProbeResult, txtPassthrough bool) (bool, string) {
	if !pr.Responded {
		return false, "no-response"
	}
	var missing []string
	if pr.HeaderOK && !pr.Header.RA {
		missing = append(missing, "no-recursion(RA=0)")
	}
	if !pr.EDNS {
		missing = append(missing, "no-edns0")
	}
	if !txtPassthrough {
		missing = append(missing, "no-txt-passthrough")
	}
	if len(missing) == 0 {
		return true, "open-recursor+edns0+txt-passthrough"
	}
	return false, strings.Join(missing, ",")
}

// txtPassthroughCheck sends a single TXT query for a domain known to carry TXT
// records and reports whether the resolver returned TXT rdata. It uses the
// configured TXT base domain when set (which the operator may control), else the
// integrity TargetDomain. Uses UDP on port 53 (or the first custom port).
func (e *Engine) txtPassthroughCheck(ctx context.Context, resolverIP string, timeout time.Duration) bool {
	txtDomain := strings.TrimSpace(e.config.DnsTxtDomain)
	if txtDomain == "" {
		txtDomain = e.config.TargetDomain
	}
	if txtDomain == "" {
		return false
	}
	port := 53
	if len(e.config.CustomPorts) > 0 {
		port = e.config.CustomPorts[0]
	}
	tp := DnsProbeTXTUDPWithDialer(ctx, resolverIP, txtDomain, timeout, e.configuredDialer(), port)
	return tp.Responded && len(tp.AnswerTXT) > 0
}

// dnsProtocolPort maps DNS protocol names to their canonical port numbers.
func dnsProtocolPort(proto string) int {
	if idx := strings.LastIndex(proto, "/"); idx != -1 && idx < len(proto)-1 {
		if port, err := strconv.Atoi(proto[idx+1:]); err == nil && port > 0 {
			return port
		}
	}
	switch proto {
	case "UDP":
		return 53
	case "TCP":
		return 53
	case "DoT":
		return 853
	case "DoH":
		return 443
	default:
		return 0
	}
}

// dnsWorker processes resolver IP targets from the jobs channel.
// For each resolver, it runs all 4 protocol probes and emits results.
func (e *Engine) dnsWorker(ctx context.Context, jobs <-chan Target, results chan<- ScanResult, truth *TruthTable) {
	defer e.wg.Done()

	timeout := time.Duration(e.config.TimeoutSecs) * time.Second
	if e.config.DnsMaxPingMs > 0 {
		timeout = time.Duration(e.config.DnsMaxPingMs) * time.Millisecond
	}
	domain := e.config.TargetDomain

	for target := range jobs {
		// Respect PAUSED or STOPPED
		if !e.checkStateOrWait(ctx) {
			results <- ScanResult{Label: target.Label, URL: target.URL, Error: "ABORTED"}
			continue
		}

		resolverIP := target.Host
		answerDomain := e.config.TargetDomain
		if e.config.DnsTxtMode {
			answerDomain = e.config.DnsTxtDomain
		}

		// Determine ports to probe: default to standard DNS behavior
		// (UDP/TCP on 53 + DoT 853 + DoH 443). Custom ports override only
		// when explicitly provided by the user.
		probePorts := e.config.CustomPorts
		if len(probePorts) == 0 {
			probePorts = nil
		}

		var probeResults []DnsProbeResult
		if e.config.DnsTxtMode {
			probeResults = DnsProbeTXT(ctx, resolverIP, answerDomain, timeout, e.configuredDialer(), e.configuredDoHClient(), probePorts)
		} else {
			// Run the layered DNS probe. Respect DnsUdpTcpOnly config flag to optionally
			// restrict probes to UDP/TCP only (no DoT/DoH).
			probeResults = DnsProbe(ctx, resolverIP, domain, truth, timeout, e.configuredDialer(), e.configuredDoHClient(), probePorts, e.config.DnsUdpTcpOnly)
		}

		// In A-record mode we don't yet know whether the resolver forwards TXT
		// rdata intact (the channel classic tunnels ride on). Run one extra TXT
		// query against a domain that actually has TXT records to find out.
		// In TXT mode each probe already carries its own passthrough signal.
		txtPassthrough := false
		if !e.config.DnsTxtMode {
			txtPassthrough = e.txtPassthroughCheck(ctx, resolverIP, timeout)
		}

		// Emit one ScanResult per protocol probe
		for _, pr := range probeResults {
			port := dnsProtocolPort(pr.Protocol)
			answerIP := ""
			answerText := ""
			if len(pr.AnswerTXT) > 0 {
				answerText = pr.AnswerTXT[0]
			}
			if len(pr.AnswerIPs) > 0 {
				answerIP = pr.AnswerIPs[0]
				if answerText == "" {
					answerText = answerIP
				}
			}

			status := 0
			errStr := pr.Error
			if pr.Responded {
				status = 1 // 1 = responded (non-HTTP, so we use 1 as "alive")
			}

			if pr.IsPoisoned {
				if errStr == "" {
					errStr = "POISONED"
				} else {
					errStr = fmt.Sprintf("%s; POISONED", errStr)
				}
			}

			// Tunnel suitability: TXT mode probes self-report passthrough; A-mode
			// probes borrow the per-resolver passthrough check above.
			txtOK := txtPassthrough
			if e.config.DnsTxtMode {
				txtOK = pr.Responded && len(pr.AnswerTXT) > 0
			}
			tunnelReady, tunnelReason := classifyTunnel(pr, txtOK)

			hdrDump := ""
			if pr.HeaderOK {
				hdrDump = pr.Header.String()
			}

			results <- ScanResult{
				Label:        target.Label,
				URL:          fmt.Sprintf("dns://%s:%d", resolverIP, port),
				ResolvedIP:   answerIP,
				DnsAnswer:    answerText,
				Port:         port,
				Status:       status,
				LatencyMs:    int(pr.TTFB.Milliseconds()),
				Error:        errStr,
				DnsProtocol:  pr.Protocol,
				IsPoisoned:   pr.IsPoisoned,
				HdrValid:     pr.HeaderOK,
				HdrDump:      hdrDump,
				RA:           pr.Header.RA,
				TC:           pr.Header.TC,
				Rcode:        int(pr.Header.Rcode),
				Edns:         pr.EDNS,
				TunnelReady:  tunnelReady,
				TunnelReason: tunnelReason,
			}
		}
	}
}
