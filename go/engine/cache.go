package engine

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func writeReportString(writer *bufio.Writer, text string) error {
	_, err := writer.WriteString(text)
	return err
}

// LoadCache returns the parsed domains from the cache file.
// Cache is never port-expanded (scanAllPorts = false).
func LoadCache(path string, scanAllPorts bool) ([]Target, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return ParseTargets(path, scanAllPorts, nil, false)
}

// SaveCache saves the successful domains to the last_passed cache.
// The caller is responsible for passing only clean/successful results.
func SaveCache(path string, results []ScanResult) error {
	if len(results) == 0 {
		return nil
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if err := writeReportString(writer, "# Auto-saved cache of last passed domains\n"); err != nil {
		return err
	}
	for _, result := range results {
		if err := writeReportString(writer, fmt.Sprintf("%s | %s\n", result.Label, result.URL)); err != nil {
			return err
		}
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

	actualTested := len(openResults) + len(deadResults) + len(poisonedResults)
	writer := bufio.NewWriter(file)

	if err := writeReportString(writer, "Reachability Report — OPEN SITES\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Generated        : %s\n", time.Now().Format("2006-01-02 15:04:05"))); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Total tested     : %d / %d\n", actualTested, total)); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Open (reachable) : %d\n", len(openResults))); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Closed / Dead    : %d\n", len(deadResults))); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Poisoned DNS     : %d\n", len(poisonedResults))); err != nil { return err }
	if err := writeReportString(writer, "============================================================================================\n\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("%-4s  %8s  %5s  %-22s  %-30s  URL\n", "#", "Latency", "HTTP", "IP : Port", "Label")); err != nil { return err }
	if err := writeReportString(writer, "--------------------------------------------------------------------------------------------\n"); err != nil { return err }

	sort.Slice(openResults, func(i, j int) bool {
		return openResults[i].LatencyMs < openResults[j].LatencyMs
	})

	for i, r := range openResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		if err := writeReportString(writer, fmt.Sprintf("%-4d  %6dms  %5d  %-22s  %-30s  %s\n", i+1, r.LatencyMs, r.Status, ipPort, r.Label, r.URL)); err != nil { return err }
	}

	if err := writeReportString(writer, "\n\n============================================================================================\n"); err != nil { return err }
	if err := writeReportString(writer, "CLOSED / UNREACHABLE (DNS/TCP/TLS/HTTP Errors)\n"); err != nil { return err }
	if err := writeReportString(writer, "============================================================================================\n"); err != nil { return err }

	sort.Slice(deadResults, func(i, j int) bool {
		return deadResults[i].Label < deadResults[j].Label
	})

	for _, r := range deadResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		if err := writeReportString(writer, fmt.Sprintf("  %-30s  %-22s  [%s]\n", r.Label, ipPort, r.Error)); err != nil { return err }
	}

	if len(poisonedResults) > 0 {
		if err := writeReportString(writer, "\n\n============================================================================================\n"); err != nil { return err }
		if err := writeReportString(writer, "POISONED DNS (DNS mode results flagged as poisoned)\n"); err != nil { return err }
		if err := writeReportString(writer, "============================================================================================\n"); err != nil { return err }

		sort.Slice(poisonedResults, func(i, j int) bool {
			return poisonedResults[i].Label < poisonedResults[j].Label
		})

		for _, r := range poisonedResults {
			ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
			if err := writeReportString(writer, fmt.Sprintf("  %-30s  %-22s  [%s]\n", r.Label, ipPort, r.Error)); err != nil { return err }
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
	if err := writeReportString(writer, "Poisoned DNS Report\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05"))); err != nil { return err }
	if err := writeReportString(writer, "============================================================================================\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("%-8s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "Error", "IP : Port", "Label")); err != nil { return err }
	if err := writeReportString(writer, "--------------------------------------------------------------------------------------------\n"); err != nil { return err }

	sort.Slice(poisonedResults, func(i, j int) bool {
		return poisonedResults[i].Label < poisonedResults[j].Label
	})

	for _, r := range poisonedResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		if err := writeReportString(writer, fmt.Sprintf("%-8s  %6dms  %-15s  %-22s  %-30s  %s\n", "POISON", r.LatencyMs, r.Error, ipPort, r.Label, r.URL)); err != nil { return err }
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
	if err := writeReportString(writer, "Reachability Report — FULL LOG\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05"))); err != nil { return err }
	if err := writeReportString(writer, "============================================================================================\n\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("%-6s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "HTTP/Err", "IP : Port", "Label")); err != nil { return err }
	if err := writeReportString(writer, "--------------------------------------------------------------------------------------------\n"); err != nil { return err }

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
		if err := writeReportString(writer, fmt.Sprintf("%-6s  %6dms  %-15s  %-22s  %-30s  %s\n", tag, r.LatencyMs, statStr, ipPort, r.Label, r.URL)); err != nil { return err }
	}

	if len(poisonedResults) > 0 {
		if err := writeReportString(writer, "\n\n============================================================================================\n"); err != nil { return err }
		if err := writeReportString(writer, "POISONED DNS (DNS mode results flagged as poisoned)\n"); err != nil { return err }
		if err := writeReportString(writer, "============================================================================================\n"); err != nil { return err }

		sort.Slice(poisonedResults, func(i, j int) bool {
			return poisonedResults[i].Label < poisonedResults[j].Label
		})

		for _, r := range poisonedResults {
			ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
			if err := writeReportString(writer, fmt.Sprintf("POISON  %6dms  %-15s  %-22s  %-30s  %s\n", r.LatencyMs, r.Error, ipPort, r.Label, r.URL)); err != nil { return err }
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
	if err := writeReportString(writer, "Hijacked DNS Report\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05"))); err != nil { return err }
	if err := writeReportString(writer, "============================================================================================\n"); err != nil { return err }
	if err := writeReportString(writer, fmt.Sprintf("%-8s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "Error", "IP : Port", "Label")); err != nil { return err }
	if err := writeReportString(writer, "--------------------------------------------------------------------------------------------\n"); err != nil { return err }

	sort.Slice(hijackedResults, func(i, j int) bool {
		return hijackedResults[i].Label < hijackedResults[j].Label
	})

	for _, r := range hijackedResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		if err := writeReportString(writer, fmt.Sprintf("%-8s  %6dms  %-15s  %-22s  %-30s  %s\n", "HIJACK", r.LatencyMs, r.Error, ipPort, r.Label, r.URL)); err != nil { return err }
	}

	return writer.Flush()
}

// SaveRawIPDump writes the unique set of resolved IPs to a plain text file.
func SaveRawIPDump(path string, openResults []ScanResult, deadResults []ScanResult, poisonedResults []ScanResult, hijackedResults []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	ipSet := make(map[string]struct{})
	addIP := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		if net.ParseIP(candidate) == nil {
			return
		}
		ipSet[candidate] = struct{}{}
	}
	addDNSResolverIP := func(result ScanResult) {
		if strings.HasPrefix(result.URL, "dns://") {
			trimmed := strings.TrimPrefix(result.URL, "dns://")
			if host, _, err := net.SplitHostPort(trimmed); err == nil {
				addIP(host)
			}
		}
		addIP(result.Label)
	}
	for _, r := range openResults {
		addIP(r.ResolvedIP)
		addDNSResolverIP(r)
	}
	for _, r := range deadResults {
		addIP(r.ResolvedIP)
		addDNSResolverIP(r)
	}
	for _, r := range poisonedResults {
		addIP(r.ResolvedIP)
		addDNSResolverIP(r)
	}
	for _, r := range hijackedResults {
		addIP(r.ResolvedIP)
		addDNSResolverIP(r)
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		if err := writeReportString(writer, ip+"\n"); err != nil {
			return err
		}
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
func WriteReports(outDir, openPath, fullPath, poisonedPath, hijackedPath, rawIPPath, cachePath string, openResults []ScanResult, deadResults []ScanResult, poisonedResults []ScanResult, total int) error {
	openFile := filepath.Join(outDir, openPath)
	fullFile := filepath.Join(outDir, fullPath)
	poisonedFile := filepath.Join(outDir, poisonedPath)
	hijackedFile := filepath.Join(outDir, hijackedPath)
	rawIPFile := filepath.Join(outDir, rawIPPath)
	cacheFile := filepath.Join(outDir, cachePath)

	hijackedResults := make([]ScanResult, 0)
	// Collect hijacked entries from all DNS-related result buckets (open, dead, poisoned)
	// Use a map to deduplicate by resolver IP + protocol to avoid repeated lines.
	seenHijack := make(map[string]struct{})
	addIfHijacked := func(r ScanResult) {
		if r.DnsProtocol == "" || r.ResolvedIP == "" {
			return
		}
		if !isHijackedIP(r.ResolvedIP) {
			return
		}
		key := fmt.Sprintf("%s|%s", r.ResolvedIP, r.DnsProtocol)
		if _, ok := seenHijack[key]; ok {
			return
		}
		seenHijack[key] = struct{}{}
		hijackedResults = append(hijackedResults, r)
	}
	for _, r := range openResults {
		addIfHijacked(r)
	}
	for _, r := range deadResults {
		addIfHijacked(r)
	}
	for _, r := range poisonedResults {
		addIfHijacked(r)
	}

	if err := SaveOpenReport(openFile, openResults, deadResults, poisonedResults, total); err != nil {
		return err
	}
	if err := SaveFullReport(fullFile, openResults, deadResults, poisonedResults); err != nil {
		return err
	}
	if err := SavePoisonedReport(poisonedFile, poisonedResults); err != nil {
		return err
	}
	if err := SaveHijackedReport(hijackedFile, hijackedResults); err != nil {
		return err
	}
	if err := SaveRawIPDump(rawIPFile, openResults, deadResults, poisonedResults, hijackedResults); err != nil {
		return err
	}
	if err := SaveCache(cacheFile, openResults); err != nil {
		return err
	}
	return nil
}
