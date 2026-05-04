package engine

// Cloudflare-supported ports for proxied traffic.
var (
	CFHTTPSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}
	CFHTTPPorts  = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}
)

// ScanConfig holds all tunable parameters for the scanner.
// Exported to allow gomobile bindings for the mobile app.
type ScanConfig struct {
	InputFile     string // Path to target list (e.g., "domains.txt")
	CacheFile     string // Path to last_passed.txt
	OutputDir     string // Output directory for reports and cache (mobile: Context.getFilesDir())
	TimeoutSecs   int    // Per-request timeout limit (default 10)
	MaxConcurrent int    // Worker pool size (default 80)
	RetryCount    int    // HTTP retry count (default 2)
	UserAgent     string // Custom User-Agent header
	ScanAllPorts  bool   // If true, expand each target across all 13 Cloudflare ports
	SpoofedSNI    string // The fake SNI to use for bypassing DPI filtering

	// Custom ports list (if non-empty, expand each host using these ports)
	CustomPorts []int

	// DNS Discovery Mode fields
	DnsDiscoveryMode bool   // If true, input file is treated as DNS resolver IPs and the engine runs DNS probes
	TargetDomain     string // Domain used for integrity verification against truth table (default "google.com")
	DnsUdpTcpOnly    bool   // If true, only run UDP/TCP probes (no DoT/DoH)
	DnsMaxPingMs     int    // Max acceptable DNS ping (ms) before marking as failed
	// Streaming mode: read targets from disk as a stream instead of loading into memory
	Streaming bool
	// If true, perform a fast line-count pass to get an accurate total for progress.
	CountTotal bool
	// Auto-concurrency uses CPU count to pick a worker pool size within limits.
	AutoConcurrency bool
	// Minimum worker pool size when auto-concurrency is enabled.
	MinConcurrent int
	// Automatically enable streaming on large input files.
	StreamingAuto bool
	// StreamingThreshold is the line count threshold to trigger auto-streaming.
	StreamingThreshold int
	// StreamingSizeMB is the file size threshold (MB) to trigger auto-streaming.
	StreamingSizeMB int
}

// DefaultConfig returns a pre-configured config mimicking the original Python settings.
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		InputFile:        "domains.txt",
		CacheFile:        "last_passed.txt",
		OutputDir:        ".",
		TimeoutSecs:      10,
		MaxConcurrent:    5000,
		RetryCount:       2,
		UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		ScanAllPorts:     false,
		SpoofedSNI:       "www.speedtest.net",
		CustomPorts:      []int{},
		DnsDiscoveryMode: false,
		TargetDomain:     "google.com",
		DnsUdpTcpOnly:    false,
		DnsMaxPingMs:     20000,
		Streaming:        false,
		CountTotal:       false,
		AutoConcurrency:  true,
		MinConcurrent:    200,
		StreamingAuto:    true,
		StreamingThreshold: 50000,
		StreamingSizeMB:  64,
	}
}
