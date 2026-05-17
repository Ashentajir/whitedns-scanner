package engine

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// buildTxtQueryName prepends a random label so TXT probes avoid cache hits.
func buildTxtQueryName(domain string) string {
	cleanDomain := strings.TrimSpace(domain)
	cleanDomain = strings.TrimSuffix(cleanDomain, ".")
	if cleanDomain == "" {
		cleanDomain = "example.invalid"
	}

	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "random." + cleanDomain
	}
	return hex.EncodeToString(nonce[:]) + "." + cleanDomain
}

// loadTxtResolverTargets resolves either a file-backed resolver list or an
// inline, comma/newline separated resolver string into scan targets.
func loadTxtResolverTargets(filePath, raw string) ([]Target, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		text = string(data)
	}

	tokens := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ',', '\n', '\r', '\t', ' ', ';':
			return true
		default:
			return false
		}
	})

	seen := make(map[string]struct{})
	targets := make([]Target, 0, len(tokens))
	for _, token := range tokens {
		target, ok := parseTxtResolverToken(token)
		if !ok {
			continue
		}
		if _, exists := seen[target.Host]; exists {
			continue
		}
		seen[target.Host] = struct{}{}
		targets = append(targets, target)
	}

	return targets, nil
}

func parseTxtResolverToken(token string) (Target, bool) {
	line := strings.TrimSpace(token)
	if line == "" || strings.HasPrefix(line, "#") {
		return Target{}, false
	}

	label := ""
	value := line
	if idx := strings.Index(line, "|"); idx != -1 {
		label = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+1:])
	}

	value = strings.Trim(value, "'\"")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "dns://"), "dns-txt://")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "udp://"), "tcp://")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")

	host := value
	if strings.Count(host, ":") == 1 {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		} else {
			parts := strings.SplitN(host, ":", 2)
			if net.ParseIP(parts[0]) != nil {
				host = parts[0]
			}
		}
	}

	if net.ParseIP(host) == nil {
		return Target{}, false
	}
	if label == "" {
		label = host
	}

	return Target{
		Label:  label,
		URL:    "dns-txt://" + host,
		Host:   host,
		Port:   53,
		Scheme: "dns",
	}, true
}
