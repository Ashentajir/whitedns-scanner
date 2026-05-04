package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Engine is the core scanner orchestrator.
type Engine struct {
	config  *ScanConfig
	handler ResultHandler

	state      string // RUNNING, PAUSED, STOPPED
	mu         sync.Mutex
	resumeChan chan struct{}
	resumeOpen bool

	cancel context.CancelFunc
	wg     sync.WaitGroup

	totalCount int
	httpClient *http.Client
	dnsDialer  *net.Dialer
	dohClient  *http.Client
}

// NewEngine creates a new scanner engine instance.
func NewEngine(config *ScanConfig, handler ResultHandler) *Engine {
	return &Engine{
		config:     config,
		handler:    handler,
		state:      "STOPPED",
		resumeChan: make(chan struct{}),
		resumeOpen: true,
	}
}

// Start begins the scanning process.
// Blocks until all scans are finished or stopped.
func (e *Engine) Start() {
	e.mu.Lock()
	// Prevent concurrent starts
	if e.state == "RUNNING" {
		e.mu.Unlock()
		return
	}
	e.state = "RUNNING"
	e.mu.Unlock()
	e.handler.OnStateChange("RUNNING")

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	cachePath := filepath.Join(e.config.OutputDir, e.config.CacheFile)
	inputPath := filepath.Join(e.config.OutputDir, e.config.InputFile)
	prioritized, _ := LoadCache(cachePath, false) // cache is never expanded to all ports

	streamingEnabled := e.config.Streaming
	if e.config.StreamingAuto {
		large, _, err := IsLargeInput(inputPath, e.config.StreamingThreshold, e.config.StreamingSizeMB)
		if err == nil && large {
			streamingEnabled = true
		}
	}

	var targets []Target
	if !streamingEnabled {
		mainTargets, err := ParseTargets(
			inputPath,
			e.config.ScanAllPorts,
			e.config.CustomPorts,
		)
		if err != nil {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: Target Parse Err: %v", err))
			return
		}

		targets = DeduplicateTargets(prioritized, mainTargets)
		e.totalCount = len(targets)
		if e.totalCount == 0 {
			return
		}
	}

	// Initialize shared high-capacity HTTP transport & client to support large concurrency
	// Tuned for many concurrent TCP connections across many hosts. We avoid per-worker
	// transports because that exhausts OS resources when scaled to thousands of goroutines.
	timeout := time.Duration(e.config.TimeoutSecs) * time.Second
	maxConns := e.resolveWorkerCount(e.totalCount)
	e.config.MaxConcurrent = maxConns
	if maxConns < 100 {
		maxConns = 100
	}

	// Determine reasonable connection pool sizes derived from desired concurrency.
	// Keep caps to avoid unbounded allocations on small machines.
	maxIdle := maxConns * 4
	if maxIdle < 1000 {
		maxIdle = 1000
	}
	if maxIdle > 20000 {
		maxIdle = 20000
	}

	// Shared DNS dialer for UDP/TCP/DoT connections — used both by DNS probes
	// and by the HTTP transport's DialContext to ensure consistent socket options.
	sharedDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	e.dnsDialer = sharedDialer

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConns:        maxIdle,
		MaxConnsPerHost:     maxConns,
		MaxIdleConnsPerHost: maxConns * 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout / 2,
		ForceAttemptHTTP2:   false,
		DialContext:         sharedDialer.DialContext,
	}
	e.httpClient = &http.Client{Transport: transport, Timeout: timeout}

	// Shared DoH client tuned for high concurrency — reuse same dialer
	dohTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConns:        maxIdle,
		MaxConnsPerHost:     maxConns,
		MaxIdleConnsPerHost: maxConns * 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout / 2,
		ForceAttemptHTTP2:   false,
		DialContext:         sharedDialer.DialContext,
	}
	e.dohClient = &http.Client{Transport: dohTransport, Timeout: timeout}

	// If streaming ingestion is enabled, prefer streaming path to avoid
	// loading the entire target list in memory (helps with very large lists).
	if streamingEnabled {
		streamCh, count, err := StreamTargets(inputPath, e.config.ScanAllPorts, e.config.CustomPorts, e.config.CountTotal)
		if err != nil {
			e.handler.OnStateChange(fmt.Sprintf("FATAL: Target Stream Err: %v", err))
			return
		}
		streamCh = prependAndFilterStream(prioritized, streamCh)
		if count > 0 {
			e.totalCount = count + len(prioritized)
		} else {
			e.totalCount = 0
		}

		// ── DNS Discovery Mode (streaming) ──
		if e.config.DnsDiscoveryMode {
			if e.totalCount > 0 {
				e.totalCount = e.totalCount * 4
			}
			e.startDnsDiscoveryStream(ctx, streamCh)
			return
		}

		// ── Standard HTTP Reachability Scan (streaming) ──
		e.startHttpScanStream(ctx, streamCh)
		return
	}

	// ── DNS Discovery Mode ──
	if e.config.DnsDiscoveryMode {
		e.startDnsDiscovery(ctx, targets)
		return
	}

	// ── Standard HTTP Reachability Scan ──
	e.startHttpScan(ctx, targets)
}

// configuredDialer returns the engine's shared DNS dialer or a default one.
func (e *Engine) configuredDialer() *net.Dialer {
	if e.dnsDialer != nil {
		return e.dnsDialer
	}
	return &net.Dialer{Timeout: time.Duration(e.config.TimeoutSecs) * time.Second}
}

// configuredDoHClient returns the engine's shared DoH HTTP client.
func (e *Engine) configuredDoHClient() *http.Client {
	if e.dohClient != nil {
		return e.dohClient
	}
	return &http.Client{Timeout: time.Duration(e.config.TimeoutSecs) * time.Second}
}

// startHttpScan runs the standard HTTP reachability scanning path.
func (e *Engine) startHttpScan(ctx context.Context, targets []Target) {
	// Use a bounded job buffer — avoid allocating a channel the size of all targets
	// when scanning millions of IPs across 13 ports.
	workers := e.resolveWorkerCount(len(targets))
	bufSize := workers * 8
	if bufSize > e.totalCount {
		bufSize = e.totalCount
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize)

	// Start workers
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.scanWorker(ctx, jobs, results)
	}

	// Feed jobs in a separate goroutine so we don't block on a full channel
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// startDnsDiscovery runs the DNS resolver discovery path.
// Each resolver IP is probed across 4 protocols, producing 4 results per target.
func (e *Engine) startDnsDiscovery(ctx context.Context, targets []Target) {
	// Initialize the Truth Table
	truth := NewTruthTable(e.config.TargetDomain)
	if err := truth.FetchTruth(); err != nil {
		// Suppress raw stdout output to prevent UI tearing during engine start.
		// Integrity Verification falls back implicitly.
	}

	// In DNS mode, each IP generates 4 results (one per protocol)
	// Adjust total for progress tracking
	e.totalCount = len(targets) * 4

	workers := e.resolveWorkerCount(len(targets))
	bufSize := workers * 8
	if bufSize > len(targets) {
		bufSize = len(targets)
	}
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize*4)

	// Start DNS workers
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.dnsWorker(ctx, jobs, results, truth)
	}

	// Feed jobs
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// collectResults is the shared result collection loop used by both scan modes.
func (e *Engine) collectResults(ctx context.Context, results chan ScanResult) {
	var openResults []ScanResult
	var deadResults []ScanResult
	var poisonedResults []ScanResult
	doneCount := 0

	// Close results channel when all workers finish
	go func() {
		e.wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.Error == "ABORTED" {
			continue
		}
		doneCount++

		e.handler.OnResult(&res)
		e.handler.OnProgress(doneCount, e.totalCount)

		// Determine success based on the active scan mode:
		//   HTTP Reachability Mode: successful iff Error is empty.
		//   DNS Discovery Mode:     successful iff Error is empty AND the
		//                           resolver is NOT poisoned.
		// Any node with an Error OR that is Poisoned belongs in deadResults.
		isSuccess := res.Error == ""
		if e.config.DnsDiscoveryMode {
			isSuccess = isSuccess && !res.IsPoisoned
		}

		if isSuccess {
			openResults = append(openResults, res)
		} else {
			deadResults = append(deadResults, res)
			if e.config.DnsDiscoveryMode && res.IsPoisoned {
				poisonedResults = append(poisonedResults, res)
			}
		}
	}

	e.mu.Lock()
	e.state = "STOPPED"
	e.mu.Unlock()
	e.handler.OnStateChange("STOPPED")

	timestamp := time.Now().Format("20060102_150405")
	openPath := fmt.Sprintf("reachable_%s.txt", timestamp)
	fullPath := fmt.Sprintf("full_log_%s.txt", timestamp)
	poisonedPath := fmt.Sprintf("poisoned_dns_%s.txt", timestamp)
	hijackedPath := fmt.Sprintf("hijacked_dns_%s.txt", timestamp)
	rawIPPath := fmt.Sprintf("raw_ip_dump_%s.txt", timestamp)

	WriteReports(e.config.OutputDir, openPath, fullPath, poisonedPath, hijackedPath, rawIPPath, e.config.CacheFile, openResults, deadResults, poisonedResults, e.totalCount)

	e.handler.OnComplete(len(openResults), len(deadResults), e.totalCount)
}

// Pause puts the engine in a paused state.
func (e *Engine) Pause() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "RUNNING" {
		e.state = "PAUSED"
		e.handler.OnStateChange("PAUSED")
	}
}

// Resume wakes the engine from a paused state.
func (e *Engine) Resume() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "PAUSED" {
		e.state = "RUNNING"
		// close resume channel only if it's open
		if e.resumeOpen {
			close(e.resumeChan)
			e.resumeOpen = false
		}
		e.resumeChan = make(chan struct{})
		e.resumeOpen = true
		e.handler.OnStateChange("RUNNING")
	}
}

// Stop safely aborts all running workers and shuts down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != "STOPPED" {
		e.state = "STOPPED"
		if e.cancel != nil {
			e.cancel()
		}
		if e.resumeOpen {
			close(e.resumeChan)
			e.resumeOpen = false
		}
		e.resumeChan = make(chan struct{})
		e.resumeOpen = true
		e.handler.OnStateChange("STOPPED")
	}
}

// startHttpScanStream runs the HTTP reachability scan using a streaming
// source of targets to avoid loading all targets in memory.
func (e *Engine) startHttpScanStream(ctx context.Context, stream <-chan Target) {
	// Use a bounded job buffer — avoid allocating a channel the size of all targets
	workers := e.resolveWorkerCount(0)
	bufSize := workers * 8
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize)

	// Start workers
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.scanWorker(ctx, jobs, results)
	}

	// Feed jobs from stream
	go func() {
		defer close(jobs)
		for t := range stream {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// startDnsDiscoveryStream runs DNS discovery using a streaming source of targets.
func (e *Engine) startDnsDiscoveryStream(ctx context.Context, stream <-chan Target) {
	// Initialize the Truth Table
	truth := NewTruthTable(e.config.TargetDomain)
	if err := truth.FetchTruth(); err != nil {
		// Suppress raw stdout output to prevent UI tearing during engine start.
		// Integrity Verification falls back implicitly.
	}

	workers := e.resolveWorkerCount(0)
	bufSize := workers * 8
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize*4)

	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.dnsWorker(ctx, jobs, results, truth)
	}

	go func() {
		defer close(jobs)
		for t := range stream {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	e.collectResults(ctx, results)
}

// prependAndFilterStream emits prioritized targets first, and then
// streams remaining targets while skipping those already in the cache.
// It only tracks cache entries to avoid unbounded memory growth.
func prependAndFilterStream(prioritized []Target, stream <-chan Target) <-chan Target {
	out := make(chan Target, 1024)
	go func() {
		defer close(out)
		seen := make(map[string]struct{}, len(prioritized))
		for _, t := range prioritized {
			if _, ok := seen[t.URL]; ok {
				continue
			}
			seen[t.URL] = struct{}{}
			out <- t
		}
		for t := range stream {
			if _, ok := seen[t.URL]; ok {
				continue
			}
			out <- t
		}
	}()
	return out
}

// resolveWorkerCount picks a worker count based on config and target count.
func (e *Engine) resolveWorkerCount(targetCount int) int {
	maxW := e.config.MaxConcurrent
	if maxW <= 0 {
		maxW = 5000
	}
	minW := e.config.MinConcurrent
	if minW <= 0 {
		minW = 50
	}
	workers := maxW
	if e.config.AutoConcurrency {
		ideal := runtime.NumCPU() * 200
		if ideal < minW {
			ideal = minW
		}
		if ideal > maxW {
			ideal = maxW
		}
		workers = ideal
	}
	if targetCount > 0 && workers > targetCount {
		workers = targetCount
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// State returns the current engine state.
func (e *Engine) State() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}
