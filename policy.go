package main

import (
	"net"
	"strings"
)

func parseList(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func isAllowed(ip string, allowlist, denylist []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if len(allowlist) > 0 {
		allowed := false
		for _, entry := range allowlist {
			if containsIP(parsed, entry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	for _, entry := range denylist {
		if containsIP(parsed, entry) {
			return false
		}
	}
	return true
}

func containsIP(ip net.IP, entry string) bool {
	if entry == "" {
		return false
	}
	if strings.Contains(entry, "/") {
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}
	return ip.Equal(net.ParseIP(entry))
}
