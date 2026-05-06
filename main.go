package main

import (
	"flag"
	"log"
	"net"
	"time"

	networkscan "github.com/enigma522/netcut-cli/networkScan"
)

func main() {
	// Existing flags.
	scanFlag  := flag.Bool("scan", false, "Scan the network")
	CIDR      := flag.String("cidr", "", "CIDR for the network scan")
	cutFlag   := flag.Bool("cut", false, "Cut off a device")
	ipAddr    := flag.String("ip", "", "IP address of the device to cut off (required if using -cut)")
	mac       := flag.String("mac", "", "MAC address of the device (optional for -cut)")
	gateway   := flag.String("g", "", "Gateway IP address")
	ifaceName := flag.String("i", "wlp49s0", "Interface name")

	// New flags.
	webFlag   := flag.Bool("web", false, "Start the web UI (served on the address given by -port)")
	port      := flag.String("port", ":8080", "Address:port for the web UI (default :8080)")
	allow     := flag.String("allow", "", "Comma-separated allowlist of IPs/MACs; only these may be cut (empty = allow all)")
	deny      := flag.String("deny", "", "Comma-separated denylist of IPs/MACs; these are never cut")
	dryRun    := flag.Bool("dry", false, "Dry-run: print what would happen but send no packets")
	durFlag   := flag.String("duration", "", "How long to cut off the device, then restore it (e.g. 30s, 5m)")

	flag.Parse()

	allowList := networkscan.ParseList(*allow)
	denyList  := networkscan.ParseList(*deny)

	var duration time.Duration
	if *durFlag != "" {
		var err error
		duration, err = time.ParseDuration(*durFlag)
		if err != nil {
			log.Fatalf("Invalid -duration value %q: %v", *durFlag, err)
		}
	}

	scanner := networkscan.NewNetworkScanner(*ifaceName)
	defer scanner.Close()

	// Web UI mode – start HTTP server and block.
	if *webFlag {
		ws := networkscan.NewWebServer(scanner, *gateway, allowList, denyList, *dryRun, *port)
		log.Fatal(ws.ListenAndServe())
		return
	}

	if *scanFlag {
		scanner.NetScan(*CIDR)
	}

	if *cutFlag {
		if *ipAddr == "" {
			log.Fatal("IP address is required when using the -cut option.")
		}

		var deviceToCut *networkscan.Device
		if *mac == "" {
			devices := scanner.NetScan(*ipAddr + "/32")
			for _, device := range devices {
				if device.IP.String() == *ipAddr {
					deviceToCut = &device
					break
				}
			}
		} else {
			macAddr, err := net.ParseMAC(*mac)
			if err != nil {
				log.Fatalf("Error parsing MAC address: %v", err)
			}
			deviceToCut = &networkscan.Device{
				IP:  net.ParseIP(*ipAddr),
				MAC: macAddr,
			}
		}

		if deviceToCut == nil {
			log.Printf("Device with IP: %s not found\n", *ipAddr)
			return
		}

		// Gateway protection.
		if networkscan.IsGateway(*deviceToCut, *gateway) {
			log.Fatal("Refusing to cut off the gateway.")
		}

		// Safety checks.
		if !networkscan.SafeToOperate(*deviceToCut, allowList, denyList, *dryRun) {
			if *dryRun {
				log.Printf("[dry-run] Would cut off device: IP: %s, MAC: %s\n", deviceToCut.IP, deviceToCut.MAC)
			} else {
				log.Printf("Operation blocked by safety policy for device: IP: %s, MAC: %s\n", deviceToCut.IP, deviceToCut.MAC)
			}
			return
		}

		log.Printf("Cut off device: IP: %s, MAC: %s, HOSTNAME: %s\n", deviceToCut.IP, deviceToCut.MAC, deviceToCut.HOSTNAME)

		if duration > 0 {
			log.Printf("Will restore device after %s\n", duration)
			scanner.CutOffDeviceFor(*deviceToCut, *gateway, duration)
		} else {
			scanner.CutOffDevice(*deviceToCut, *gateway)
		}
	}
}
