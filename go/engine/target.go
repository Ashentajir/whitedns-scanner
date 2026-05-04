package engine

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Target represents a single scan end-point with an explicit port and scheme.
type Target struct {
	Label  string
	URL    string
	Host   string // Original hostname/domain (used for SNI / Host header spoofing)
	Port   int    // Explicit port to probe
	Scheme string // "https" or "http"
}

// ParseTargets reads domains.txt or Cache and parses them into Target slices.
// If scanAllPorts is true, each domain is expanded into 13 targets (one per CF port).
// If customPorts is non-empty, each host is expanded across the provided ports.
func ParseTargets(filePath string, scanAllPorts bool, customPorts []int) ([]Target, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rawTargets []Target
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lbl := ""
		val := line

		if idx := strings.Index(line, "|"); idx != -1 {
			lbl = strings.TrimSpace(line[:idx])
			val = strings.TrimSpace(line[idx+1:])
		}

		val = strings.Trim(val, "'\"")

		// Handle CIDR blocks (e.g. 104.18.2.0/24)
		if strings.Contains(val, "/") && !strings.HasPrefix(val, "http") {
			ip, ipnet, err := net.ParseCIDR(val)
			if err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
					ipStr := ip.String()
					if ipStr == ipnet.IP.String() {
						continue // skip network address
					}

					tLbl := ipStr
					if lbl != "" {
						tLbl = fmt.Sprintf("%s %s", lbl, ipStr)
					}
					rawTargets = append(rawTargets, Target{
						Label:  strings.TrimSpace(tLbl),
						URL:    "https://" + ipStr,
						Host:   ipStr,
						Port:   443,
						Scheme: "https",
					})
				}
				// Remove the last IP (broadcast address)
				if len(rawTargets) > 0 {
					rawTargets = rawTargets[:len(rawTargets)-1]
				}
				continue
			}
		}

		// Standard domain or single IP
		var host, scheme string
		if strings.HasPrefix(val, "http://") {
			scheme = "http"
			host = strings.TrimPrefix(val, "http://")
			host = strings.SplitN(host, "/", 2)[0]
		} else if strings.HasPrefix(val, "https://") {
			scheme = "https"
			host = strings.TrimPrefix(val, "https://")
			host = strings.SplitN(host, "/", 2)[0]
		} else {
			scheme = "https"
			host = val
		}

		finalLbl := lbl
		if finalLbl == "" {
			finalLbl = host
		}

		port := 443
		if scheme == "http" {
			port = 80
		}

		rawTargets = append(rawTargets, Target{
			Label:  finalLbl,
			URL:    scheme + "://" + host,
			Host:   host,
			Port:   port,
			Scheme: scheme,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// If ScanAllPorts is enabled, expand each unique host across all 13 CF ports.
	if scanAllPorts {
		return expandAllPorts(rawTargets), nil
	}

	// If custom ports are provided, expand using those ports.
	if len(customPorts) > 0 {
		return expandCustomPorts(rawTargets, customPorts), nil
	}

	return rawTargets, nil
}

// StreamTargets returns a channel that will produce Target items parsed from
// the provided file. It spawns a goroutine that reads the file and sends
// parsed targets to the channel. The returned `count` is an estimated total
// when it can be determined cheaply; otherwise it is -1.
func StreamTargets(filePath string, scanAllPorts bool, customPorts []int, countTotal bool) (<-chan Target, int, error) {
	// If countTotal requested and expansion isn't needed, perform a quick line count.
	total := -1
	if countTotal && !scanAllPorts && len(customPorts) == 0 {
		f, err := os.Open(filePath)
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			n := 0
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				n++
			}
			if err := sc.Err(); err == nil {
				total = n
			} else {
				total = -1
			}
		}
	}

	out := make(chan Target, 1024)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, -1, err
	}

	go func() {
		defer file.Close()
		defer close(out)

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			lbl := ""
			val := line

			if idx := strings.Index(line, "|"); idx != -1 {
				lbl = strings.TrimSpace(line[:idx])
				val = strings.TrimSpace(line[idx+1:])
			}

			val = strings.Trim(val, "'\"")

			// Handle CIDR blocks (e.g. 104.18.2.0/24)
			if strings.Contains(val, "/") && !strings.HasPrefix(val, "http") {
				ip, ipnet, err := net.ParseCIDR(val)
				if err == nil {
					broadcast := broadcastIPv4(ipnet)
					for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
						ipStr := ip.String()
						if ipStr == ipnet.IP.String() {
							continue // skip network address
						}
						if broadcast != nil && ipStr == broadcast.String() {
							continue // skip broadcast address
						}
						tLbl := ipStr
						if lbl != "" {
							tLbl = fmt.Sprintf("%s %s", lbl, ipStr)
						}
						out <- Target{Label: strings.TrimSpace(tLbl), URL: "https://" + ipStr, Host: ipStr, Port: 443, Scheme: "https"}
					}
					// NOTE: we do not remove a final broadcast entry here; Senders
					// will stream what they generate.
					continue
				}
			}

			// Standard domain or single IP
			var host, scheme string
			if strings.HasPrefix(val, "http://") {
				scheme = "http"
				host = strings.TrimPrefix(val, "http://")
				host = strings.SplitN(host, "/", 2)[0]
			} else if strings.HasPrefix(val, "https://") {
				scheme = "https"
				host = strings.TrimPrefix(val, "https://")
				host = strings.SplitN(host, "/", 2)[0]
			} else {
				scheme = "https"
				host = val
			}

			finalLbl := lbl
			if finalLbl == "" {
				finalLbl = host
			}

			port := 443
			if scheme == "http" {
				port = 80
			}

			// If scanAllPorts or customPorts are set, expand per-host here
			if scanAllPorts {
				for _, p := range CFHTTPSPorts {
					out <- Target{Label: fmt.Sprintf("%s:%d", finalLbl, p), URL: fmt.Sprintf("https://%s:%d", host, p), Host: host, Port: p, Scheme: "https"}
				}
				for _, p := range CFHTTPPorts {
					out <- Target{Label: fmt.Sprintf("%s:%d", finalLbl, p), URL: fmt.Sprintf("http://%s:%d", host, p), Host: host, Port: p, Scheme: "http"}
				}
				continue
			}

			if len(customPorts) > 0 {
				for _, p := range customPorts {
					schemeUse := scheme
					if schemeUse == "" {
						schemeUse = "https"
					}
					out <- Target{Label: fmt.Sprintf("%s:%d", finalLbl, p), URL: fmt.Sprintf("%s://%s:%d", schemeUse, host, p), Host: host, Port: p, Scheme: schemeUse}
				}
				continue
			}

			out <- Target{Label: finalLbl, URL: scheme + "://" + host, Host: host, Port: port, Scheme: scheme}
		}
	}()

	return out, total, nil
}

// EstimateScannableLines counts non-empty, non-comment lines until a limit is reached.
// Returns the number counted and whether the limit was exceeded.
func EstimateScannableLines(filePath string, limit int) (int, bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if limit > 0 && count > limit {
			return count, true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return count, false, err
	}
	return count, false, nil
}

// IsLargeInput determines whether the input file should trigger streaming mode.
func IsLargeInput(filePath string, lineThreshold int, sizeMB int) (bool, int, error) {
	if sizeMB > 0 {
		info, err := os.Stat(filePath)
		if err == nil {
			if info.Size() >= int64(sizeMB)*1024*1024 {
				return true, -1, nil
			}
		}
	}
	if lineThreshold <= 0 {
		return false, -1, nil
	}
	count, exceeded, err := EstimateScannableLines(filePath, lineThreshold)
	if err != nil {
		return false, -1, err
	}
	if exceeded {
		return true, count, nil
	}
	return false, count, nil
}

// broadcastIPv4 returns the broadcast address for an IPv4 CIDR, or nil for IPv6.
func broadcastIPv4(ipnet *net.IPNet) net.IP {
	if ipnet == nil {
		return nil
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipnet.Mask
	if len(mask) != net.IPv4len {
		return nil
	}
	b := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		b[i] = ip[i] | ^mask[i]
	}
	return b
}

// expandAllPorts takes a list of raw targets and for each unique host, creates
// one target per Cloudflare port (6 HTTPS + 7 HTTP = 13 per host).
func expandAllPorts(rawTargets []Target) []Target {
	var expanded []Target
	seen := make(map[string]struct{}) // track host to avoid double-expanding

	for _, t := range rawTargets {
		if _, exists := seen[t.Host]; exists {
			continue
		}
		seen[t.Host] = struct{}{}

		for _, port := range CFHTTPSPorts {
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, port),
				URL:    fmt.Sprintf("https://%s:%d", t.Host, port),
				Host:   t.Host,
				Port:   port,
				Scheme: "https",
			})
		}
		for _, port := range CFHTTPPorts {
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, port),
				URL:    fmt.Sprintf("http://%s:%d", t.Host, port),
				Host:   t.Host,
				Port:   port,
				Scheme: "http",
			})
		}
	}

	return expanded
}

// expandCustomPorts expands each unique host into targets using the provided ports.
func expandCustomPorts(rawTargets []Target, ports []int) []Target {
	var expanded []Target
	seen := make(map[string]struct{})
	for _, t := range rawTargets {
		if _, exists := seen[t.Host]; exists {
			continue
		}
		seen[t.Host] = struct{}{}

		for _, p := range ports {
			scheme := t.Scheme
			if scheme == "" {
				scheme = "https"
			}
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, p),
				URL:    fmt.Sprintf("%s://%s:%d", scheme, t.Host, p),
				Host:   t.Host,
				Port:   p,
				Scheme: scheme,
			})
		}
	}
	return expanded
}

// DeduplicateTargets returns a unique slice of targets, keeping the order of prioritized first.
func DeduplicateTargets(prioritized []Target, main []Target) []Target {
	seen := make(map[string]struct{})
	var result []Target

	for _, t := range prioritized {
		if _, exists := seen[t.URL]; !exists {
			seen[t.URL] = struct{}{}
			result = append(result, t)
		}
	}

	for _, t := range main {
		if _, exists := seen[t.URL]; !exists {
			seen[t.URL] = struct{}{}
			result = append(result, t)
		}
	}

	return result
}

// incIP increments an IP address.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
