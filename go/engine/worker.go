package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
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
			if scheme == "https" {
				// Try HTTP fallback on port 80
				fallbackResult := PreFlightLayerCheck(ctx, host, 80, "http", layerTimeout, "")
				if fallbackResult.Status == "PASSED" {
					scheme = "http"
					port = 80
					probeResult = fallbackResult
				} else {
					results <- ScanResult{
						Label:      target.Label,
						URL:        target.URL,
						ResolvedIP: probeResult.ResolvedIP,
						Port:       port,
						LatencyMs:  int(time.Since(start).Milliseconds()),
						Error:      probeResult.Status,
					}
					continue
				}
			} else {
				results <- ScanResult{
					Label:      target.Label,
					URL:        target.URL,
					ResolvedIP: probeResult.ResolvedIP,
					Port:       port,
					LatencyMs:  int(time.Since(start).Milliseconds()),
					Error:      probeResult.Status,
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

// dnsProtocolPort maps DNS protocol names to their canonical port numbers.
func dnsProtocolPort(proto string) int {
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

		// Determine ports to probe: default to standard DNS behavior
		// (UDP/TCP on 53 + DoT 853 + DoH 443). Custom ports override only
		// when explicitly provided by the user.
		probePorts := e.config.CustomPorts
		if len(probePorts) == 0 {
			probePorts = nil
		}

		// Run the layered DNS probe. Respect DnsUdpTcpOnly config flag to optionally
		// restrict probes to UDP/TCP only (no DoT/DoH).
		probeResults := DnsProbe(ctx, resolverIP, domain, truth, timeout, e.configuredDialer(), e.configuredDoHClient(), probePorts, e.config.DnsUdpTcpOnly)

		// Emit one ScanResult per protocol probe
		for _, pr := range probeResults {
			port := dnsProtocolPort(pr.Protocol)
			answerIP := ""
			if len(pr.AnswerIPs) > 0 {
				answerIP = pr.AnswerIPs[0]
			}

			status := 0
			errStr := pr.Error
			if pr.Responded {
				status = 1 // 1 = responded (non-HTTP, so we use 1 as "alive")
				errStr = ""
			}

			results <- ScanResult{
				Label:       target.Label,
				URL:         fmt.Sprintf("dns://%s:%d", resolverIP, port),
				ResolvedIP:  answerIP,
				Port:        port,
				Status:      status,
				LatencyMs:   int(pr.TTFB.Milliseconds()),
				Error:       errStr,
				DnsProtocol: pr.Protocol,
				IsPoisoned:  pr.IsPoisoned,
			}
		}
	}
}
