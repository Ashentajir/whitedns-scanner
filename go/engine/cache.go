package engine

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// LoadCache returns the parsed domains from the cache file.
// Cache is never port-expanded (scanAllPorts = false).
func LoadCache(path string, scanAllPorts bool) ([]Target, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return ParseTargets(path, scanAllPorts, nil)
}

// SaveCache saves the successful domains to the last_passed cache.
// The caller is responsible for passing only clean/successful results.
func SaveCache(path string, results []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("# Auto-saved cache of last passed domains\n")
	for _, result := range results {
		writer.WriteString(fmt.Sprintf("%s | %s\n", result.Label, result.URL))
	}
	return writer.Flush()
}

// SaveOpenReport generates the text report for open targets.
// Now includes ResolvedIP and Port columns.
func SaveOpenReport(path string, openResults []ScanResult, deadResults []ScanResult, poisonedResults []ScanResult, total int) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	actualTested := len(openResults) + len(deadResults)
	writer := bufio.NewWriter(file)

	writer.WriteString("Reachability Report — OPEN SITES\n")
	writer.WriteString(fmt.Sprintf("Generated        : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Total tested     : %d / %d\n", actualTested, total))
	writer.WriteString(fmt.Sprintf("Open (reachable) : %d\n", len(openResults)))
	writer.WriteString(fmt.Sprintf("Closed / Dead    : %d\n", len(deadResults)))
	writer.WriteString(fmt.Sprintf("Poisoned DNS     : %d\n", len(poisonedResults)))
	writer.WriteString("============================================================================================\n\n")
	writer.WriteString(fmt.Sprintf("%-4s  %8s  %5s  %-22s  %-30s  URL\n", "#", "Latency", "HTTP", "IP : Port", "Label"))
	writer.WriteString("--------------------------------------------------------------------------------------------\n")

	sort.Slice(openResults, func(i, j int) bool {
		return openResults[i].LatencyMs < openResults[j].LatencyMs
	})

	for i, r := range openResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("%-4d  %6dms  %5d  %-22s  %-30s  %s\n", i+1, r.LatencyMs, r.Status, ipPort, r.Label, r.URL))
	}

	writer.WriteString("\n\n============================================================================================\n")
	writer.WriteString("CLOSED / UNREACHABLE (DNS/TCP/TLS/HTTP Errors)\n")
	writer.WriteString("============================================================================================\n")

	sort.Slice(deadResults, func(i, j int) bool {
		return deadResults[i].Label < deadResults[j].Label
	})

	for _, r := range deadResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("  %-30s  %-22s  [%s]\n", r.Label, ipPort, r.Error))
	}

	if len(poisonedResults) > 0 {
		writer.WriteString("\n\n============================================================================================\n")
		writer.WriteString("POISONED DNS (DNS mode results flagged as poisoned)\n")
		writer.WriteString("============================================================================================\n")

		sort.Slice(poisonedResults, func(i, j int) bool {
			return poisonedResults[i].Label < poisonedResults[j].Label
		})

		for _, r := range poisonedResults {
			ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
			writer.WriteString(fmt.Sprintf("  %-30s  %-22s  [%s]\n", r.Label, ipPort, r.Error))
		}
	}

	return writer.Flush()
}

// SavePoisonedReport generates a standalone report for poisoned DNS results.
func SavePoisonedReport(path string, poisonedResults []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("Poisoned DNS Report\n")
	writer.WriteString(fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString("============================================================================================\n")
	writer.WriteString(fmt.Sprintf("%-8s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "Error", "IP : Port", "Label"))
	writer.WriteString("--------------------------------------------------------------------------------------------\n")

	sort.Slice(poisonedResults, func(i, j int) bool {
		return poisonedResults[i].Label < poisonedResults[j].Label
	})

	for _, r := range poisonedResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("%-8s  %6dms  %-15s  %-22s  %-30s  %s\n", "POISON", r.LatencyMs, r.Error, ipPort, r.Label, r.URL))
	}

	return writer.Flush()
}

// SaveFullReport generates the full log report with IP:Port.
func SaveFullReport(path string, openResults []ScanResult, deadResults []ScanResult, poisonedResults []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("Reachability Report — FULL LOG\n")
	writer.WriteString(fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString("============================================================================================\n\n")
	writer.WriteString(fmt.Sprintf("%-6s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "HTTP/Err", "IP : Port", "Label"))
	writer.WriteString("--------------------------------------------------------------------------------------------\n")

	var allRows []ScanResult
	allRows = append(allRows, openResults...)
	allRows = append(allRows, deadResults...)

	sort.Slice(allRows, func(i, j int) bool {
		return allRows[i].Label < allRows[j].Label
	})

	for _, r := range allRows {
		tag := "OPEN"
		statStr := fmt.Sprintf("%d", r.Status)
		if r.Error != "" {
			tag = "DEAD"
			statStr = r.Error
			if statStr == "" {
				statStr = "DEAD"
			}
		}
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("%-6s  %6dms  %-15s  %-22s  %-30s  %s\n", tag, r.LatencyMs, statStr, ipPort, r.Label, r.URL))
	}

	if len(poisonedResults) > 0 {
		writer.WriteString("\n\n============================================================================================\n")
		writer.WriteString("POISONED DNS (DNS mode results flagged as poisoned)\n")
		writer.WriteString("============================================================================================\n")

		sort.Slice(poisonedResults, func(i, j int) bool {
			return poisonedResults[i].Label < poisonedResults[j].Label
		})

		for _, r := range poisonedResults {
			ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
			writer.WriteString(fmt.Sprintf("POISON  %6dms  %-15s  %-22s  %-30s  %s\n", r.LatencyMs, r.Error, ipPort, r.Label, r.URL))
		}
	}

	return writer.Flush()
}

// SaveHijackedReport generates a standalone report for hijacked DNS results.
func SaveHijackedReport(path string, hijackedResults []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("Hijacked DNS Report\n")
	writer.WriteString(fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString("============================================================================================\n")
	writer.WriteString(fmt.Sprintf("%-8s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "Error", "IP : Port", "Label"))
	writer.WriteString("--------------------------------------------------------------------------------------------\n")

	sort.Slice(hijackedResults, func(i, j int) bool {
		return hijackedResults[i].Label < hijackedResults[j].Label
	})

	for _, r := range hijackedResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("%-8s  %6dms  %-15s  %-22s  %-30s  %s\n", "HIJACK", r.LatencyMs, r.Error, ipPort, r.Label, r.URL))
	}

	return writer.Flush()
}

// SaveRawIPDump writes the unique set of resolved IPs to a plain text file.
func SaveRawIPDump(path string, openResults []ScanResult, deadResults []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	ipSet := make(map[string]struct{})
	for _, r := range openResults {
		if r.ResolvedIP != "" {
			ipSet[r.ResolvedIP] = struct{}{}
		}
	}
	for _, r := range deadResults {
		if r.ResolvedIP != "" {
			ipSet[r.ResolvedIP] = struct{}{}
		}
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		writer.WriteString(ip + "\n")
	}
	return writer.Flush()
}

func isHijackedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 10 {
		return true
	}
	if v4[0] == 127 {
		return true
	}
	if v4[0] == 169 && v4[1] == 254 {
		return true
	}
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return true
	}
	if v4[0] == 192 && v4[1] == 168 {
		return true
	}
	if v4[0] == 0 {
		return true
	}
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
		return true
	}
	return false
}

// WriteReports is a helper to write all logs at once to a specific directory.
func WriteReports(outDir, openPath, fullPath, poisonedPath, hijackedPath, rawIPPath, cachePath string, openResults []ScanResult, deadResults []ScanResult, poisonedResults []ScanResult, total int) {
	openFile := filepath.Join(outDir, openPath)
	fullFile := filepath.Join(outDir, fullPath)
	poisonedFile := filepath.Join(outDir, poisonedPath)
	hijackedFile := filepath.Join(outDir, hijackedPath)
	rawIPFile := filepath.Join(outDir, rawIPPath)
	cacheFile := filepath.Join(outDir, cachePath)

	hijackedResults := make([]ScanResult, 0)
	for _, r := range deadResults {
		if r.DnsProtocol != "" && isHijackedIP(r.ResolvedIP) {
			hijackedResults = append(hijackedResults, r)
		}
	}

	SaveOpenReport(openFile, openResults, deadResults, poisonedResults, total)
	SaveFullReport(fullFile, openResults, deadResults, poisonedResults)
	SavePoisonedReport(poisonedFile, poisonedResults)
	SaveHijackedReport(hijackedFile, hijackedResults)
	SaveRawIPDump(rawIPFile, openResults, deadResults)
	SaveCache(cacheFile, openResults)
}
