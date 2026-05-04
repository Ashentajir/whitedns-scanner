package engine

// ScanResult holds the outcome of a single URL probe.
// Exported for gomobile compatibility — only basic types.
type ScanResult struct {
	Label      string
	URL        string
	ResolvedIP string // The actual IP address we connected to (DPI bypass)
	Port       int    // The port scanned (e.g., 443, 8443, 80)
	Status     int    // HTTP status code, 0 if it failed before finishing HTTP request
	LatencyMs  int    // Total latency in milliseconds
	Error      string // Empty string implies success

	// DNS Discovery Mode fields (empty/false for regular HTTP scans)
	DnsProtocol string // "UDP", "TCP", "DoT", "DoH", or "" for non-DNS scans
	IsPoisoned  bool   // true if the resolver returned an IP mismatching the truth table
}

// ResultHandler is a callback interface for delivering events out of the engine.
// Gomobile binds this as an interface for Java/Swift bridging.
type ResultHandler interface {
	OnResult(result *ScanResult)
	OnProgress(done, total int)
	OnStateChange(state string) // "RUNNING", "PAUSED", "STOPPED"
	OnComplete(openCount, deadCount, totalCount int)
}
