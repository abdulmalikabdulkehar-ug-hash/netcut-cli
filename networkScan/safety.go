package networkscan

import (
	"net"
	"strings"
)

// ParseList parses a comma-separated string of IPs or MACs into a slice of
// normalised lowercase strings. Empty entries are ignored.
func ParseList(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, entry := range strings.Split(csv, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			out = append(out, strings.ToLower(entry))
		}
	}
	return out
}

// matchesEntry returns true when device IP or MAC matches the given entry
// string. Both IP and hardware-address comparison are normalised to lowercase.
func matchesEntry(device Device, entry string) bool {
	if device.IP != nil && device.IP.String() == entry {
		return true
	}
	if device.MAC != nil && strings.ToLower(device.MAC.String()) == entry {
		return true
	}
	return false
}

// IsAllowed reports whether the device should be operated on when an allowlist
// is active.  If the allowlist is empty every device is considered allowed.
func IsAllowed(device Device, allowList []string) bool {
	if len(allowList) == 0 {
		return true
	}
	for _, entry := range allowList {
		if matchesEntry(device, entry) {
			return true
		}
	}
	return false
}

// IsDenied reports whether the device appears on the denylist and therefore
// must not be touched.  If the denylist is empty no device is denied.
func IsDenied(device Device, denyList []string) bool {
	for _, entry := range denyList {
		if matchesEntry(device, entry) {
			return true
		}
	}
	return false
}

// SafeToOperate returns true when it is safe to operate on device given the
// current allow and deny lists, and dry-run flag.
// When dryRun is true the function always returns false (no packets sent).
func SafeToOperate(device Device, allowList, denyList []string, dryRun bool) bool {
	if dryRun {
		return false
	}
	if IsDenied(device, denyList) {
		return false
	}
	return IsAllowed(device, allowList)
}

// IsGateway returns true when the device IP matches the gateway address.
// Callers should always protect the gateway from cut-off.
func IsGateway(device Device, gateway string) bool {
	gw := net.ParseIP(gateway)
	if gw == nil {
		return false
	}
	return gw.Equal(device.IP)
}
