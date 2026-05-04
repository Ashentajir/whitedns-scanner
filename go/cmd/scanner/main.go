package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"reachability-scanner/engine"
	"reachability-scanner/internal/tui"
)

func main() {
	var input string
	var outDir string
	var concurrent int
	var timeout int
	var retry int
	var allPorts bool
	var dnsMode bool
	var portsFlag string
	var dnsDomain string
	var spoofSNI string
	var autoConcurrency bool
	var minConcurrent int
	var streaming bool
	var streamingAuto bool
	var streamingThreshold int
	var streamingSizeMB int
	var countTotal bool

	flag.StringVar(&input, "input", "domains.txt", "Path to target list")
	flag.StringVar(&outDir, "out", ".", "Directory to output reports and cache")
	flag.IntVar(&concurrent, "concurrent", -1, "Worker pool size (<=0 for auto)")
	flag.IntVar(&timeout, "timeout", 10, "Per-request timeout limit (seconds)")
	flag.IntVar(&retry, "retry", 2, "HTTP retry count")
	flag.BoolVar(&allPorts, "allports", false, "Scan all 13 Cloudflare ports per host")
	flag.BoolVar(&dnsMode, "dns", false, "DNS Discovery Mode: probe resolver IPs across UDP/TCP/DoT/DoH")
	flag.StringVar(&portsFlag, "ports", "", "Custom ports (comma-separated or ranges, e.g. 80,443,8000-8010)")
	flag.StringVar(&dnsDomain, "domain", "google.com", "Target domain for DNS integrity verification")
	flag.StringVar(&spoofSNI, "sni", "www.speedtest.net", "Spoofed SNI for DPI bypass (e.g. zula.ir)")
	flag.BoolVar(&autoConcurrency, "autoconcurrency", true, "Auto-tune worker pool size")
	flag.IntVar(&minConcurrent, "minconcurrency", 200, "Minimum workers when auto-tuning")
	flag.BoolVar(&streaming, "streaming", false, "Force streaming input mode")
	flag.BoolVar(&streamingAuto, "streaming-auto", true, "Auto-enable streaming for large inputs")
	flag.IntVar(&streamingThreshold, "streaming-threshold", 50000, "Line count to trigger streaming")
	flag.IntVar(&streamingSizeMB, "streaming-size-mb", 64, "File size (MB) to trigger streaming")
	flag.BoolVar(&countTotal, "count-total", false, "Count total lines for progress (extra pass)")
	flag.Parse()

	cfg := engine.DefaultConfig()
	cfg.InputFile = input
	cfg.OutputDir = outDir
	cfg.AutoConcurrency = autoConcurrency
	cfg.MinConcurrent = minConcurrent
	cfg.Streaming = streaming
	cfg.StreamingAuto = streamingAuto
	cfg.StreamingThreshold = streamingThreshold
	cfg.StreamingSizeMB = streamingSizeMB
	cfg.CountTotal = countTotal
	if concurrent > 0 {
		cfg.MaxConcurrent = concurrent
		cfg.AutoConcurrency = false
	}
	cfg.TimeoutSecs = timeout
	cfg.RetryCount = retry
	cfg.ScanAllPorts = allPorts
	if portsFlag != "" {
		cfg.CustomPorts = parsePortsString(portsFlag)
	}
	cfg.DnsDiscoveryMode = dnsMode
	cfg.TargetDomain = dnsDomain
	cfg.SpoofedSNI = spoofSNI

	interactive := len(os.Args) == 1

	for {
		if interactive {
			runInteractiveSetup(cfg)
		}

		// Validate input file exists
		if _, err := os.Stat(cfg.InputFile); os.IsNotExist(err) {
			fmt.Printf("  Error: Could not find target file '%s'\n", cfg.InputFile)
			if !interactive {
				os.Exit(1)
			}
		} else {
			// Run the TUI Model
			model := tui.NewModel(cfg)
			if err := model.Run(cfg); err != nil {
				fmt.Printf("Error running scanner: %v\n", err)
			}
		}

		// POST-SCAN MENU
		for {
			fmt.Println("\n╔══════════════════════════════════════════════════════╗")
			fmt.Println("║               ENTERPRISE POST-SCAN MENU              ║")
			fmt.Println("╚══════════════════════════════════════════════════════╝")
			fmt.Println("  [1] Re-run scan with current configuration")
			fmt.Println("  [2] Change configuration / Scan Mode")
			fmt.Println("  [3] Open output directory (Reports & Cache)")
			fmt.Println("  [4] Exit Application")
			fmt.Printf("\n  Select an option (1-4): ")

			var choice string
			// We use fmt.Scanln to read the single option
			fmt.Scanln(&choice)
			choice = strings.TrimSpace(choice)

			if choice == "1" {
				interactive = false
				break
			} else if choice == "2" {
				interactive = true
				break
			} else if choice == "3" {
				openDir(cfg.OutputDir)
			} else if choice == "4" || strings.ToLower(choice) == "q" {
				fmt.Println("  Exiting... Goodbye.")
				return
			} else {
				fmt.Println("  Invalid option. Please enter 1-4.")
			}
		}
	}
}

func runInteractiveSetup(cfg *engine.ScanConfig) {
	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║     ENTERPRISE REACHABILITY SCANNER - Setup         ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Prompt for target file
	fmt.Printf("  Enter target list file (Default: %s): ", cfg.InputFile)
	var userInput string
	fmt.Scanln(&userInput)
	if userInput != "" {
		cfg.InputFile = strings.TrimSpace(userInput)
	}

	// Prompt for concurrent connections
	fmt.Printf("  Enter concurrent connections (Default: %d): ", cfg.MaxConcurrent)
	var concInput string
	fmt.Scanln(&concInput)
	if concInput != "" {
		fmt.Sscanf(concInput, "%d", &cfg.MaxConcurrent)
		if cfg.MaxConcurrent > 0 {
			cfg.AutoConcurrency = false
		}
	}

	// Prompt for Spoofed SNI
	fmt.Printf("  Enter Spoofed SNI for DPI Bypass (Default: %s): ", cfg.SpoofedSNI)
	var sniInput string
	fmt.Scanln(&sniInput)
	sniInput = strings.TrimSpace(sniInput)
	if sniInput != "" {
		cfg.SpoofedSNI = sniInput
	}

	// Prompt for scanning mode
	fmt.Println()
	fmt.Println("  Scanning Mode:")
	fmt.Println("    [1] Default Ports (443/80 only) — Fast")
	fmt.Println("    [2] All Cloudflare Ports (13 ports) — Deep Scan")
	fmt.Println("    [3] DNS Resolver Discovery — Probe resolvers (UDP/TCP/DoT/DoH)")
	fmt.Println("    [4] DNS UDP/TCP only — faster, no DoT/DoH")
	fmt.Println("    [5] Custom ports — enter a list or ranges (e.g. 80,443,8000-8010)")

	defaultMode := "1"
	if cfg.DnsDiscoveryMode {
		defaultMode = "3"
	} else if cfg.ScanAllPorts {
		defaultMode = "2"
	}
	fmt.Printf("  Select mode (Default: %s): ", defaultMode)

	var modeInput string
	fmt.Scanln(&modeInput)
	modeInput = strings.TrimSpace(modeInput)
	if modeInput == "" {
		modeInput = defaultMode
	}

	switch modeInput {
	case "1":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = false
		cfg.DnsUdpTcpOnly = false
	case "2":
		cfg.ScanAllPorts = true
		cfg.DnsDiscoveryMode = false
		cfg.DnsUdpTcpOnly = false
	case "3":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = true
		cfg.DnsUdpTcpOnly = false
		fmt.Printf("  Enter integrity check domain (Default: %s): ", cfg.TargetDomain)
		var domainInput string
		fmt.Scanln(&domainInput)
		domainInput = strings.TrimSpace(domainInput)
		if domainInput != "" {
			cfg.TargetDomain = domainInput
		}
	case "4":
		cfg.ScanAllPorts = false
		cfg.DnsDiscoveryMode = true
		cfg.DnsUdpTcpOnly = true
		fmt.Printf("  Enter integrity check domain (Default: %s): ", cfg.TargetDomain)
		var domainInput2 string
		fmt.Scanln(&domainInput2)
		domainInput2 = strings.TrimSpace(domainInput2)
		if domainInput2 != "" {
			cfg.TargetDomain = domainInput2
		}
	case "5":
		// Custom ports - apply to non-DNS scans. If DNS mode is wanted, user should
		// select 3 or 4 above and then also enter custom ports using flag or prompt.
		fmt.Printf("  Enter custom ports (e.g. 80,443,8000-8010): ")
		var portsInput string
		fmt.Scanln(&portsInput)
		portsInput = strings.TrimSpace(portsInput)
		if portsInput != "" {
			cfg.CustomPorts = parsePortsString(portsInput)
		}
	}

	fmt.Println()
	if cfg.DnsDiscoveryMode {
		fmt.Printf("  ⚡ Mode: DNS RESOLVER DISCOVERY (domain: %s)\n", cfg.TargetDomain)
	} else if cfg.ScanAllPorts {
		fmt.Println("  ⚡ Mode: ALL CLOUDFLARE PORTS (13 per host)")
	} else {
		fmt.Println("  ⚡ Mode: DEFAULT PORTS (443/80)")
	}
	fmt.Println()
}

func openDir(dir string) {
	if dir == "." || dir == "" {
		dir = "."
	}
	// For Windows Explorer
	cmd := exec.Command("explorer", dir)
	if err := cmd.Start(); err != nil {
		fmt.Printf("  [!] Failed to open directory: %v\n", err)
	} else {
		fmt.Println("  [+] Opened output directory.")
	}
}

// parsePortsString accepts comma-separated ports and ranges like 8000-8010
func parsePortsString(s string) []int {
	out := make(map[int]struct{})
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			a := 0
			b := 0
			fmt.Sscanf(bounds[0], "%d", &a)
			fmt.Sscanf(bounds[1], "%d", &b)
			if a > b {
				a, b = b, a
			}
			for i := a; i <= b; i++ {
				if i >= 1 && i <= 65535 {
					out[i] = struct{}{}
				}
			}
		} else {
			v := 0
			fmt.Sscanf(p, "%d", &v)
			if v >= 1 && v <= 65535 {
				out[v] = struct{}{}
			}
		}
	}
	res := make([]int, 0, len(out))
	for k := range out {
		res = append(res, k)
	}
	// sort for deterministic order
	sort.Ints(res)
	return res
}
