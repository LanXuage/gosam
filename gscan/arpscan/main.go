package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ARPInterface struct {
	Name    string
	Gateway net.IP
	Mask    uint32
	Handle  *pcap.Handle
}

type ARPScanResult struct {
	IP     net.IP
	Mac    net.HardwareAddr
	Vendor string
}

type ARPMap map[uint32]net.HardwareAddr

type ARPScanner struct {
	State   int8
	Opts    gopacket.SerializeOptions
	Timeout time.Duration
	ARPIfs  []ARPInterface
	Maps    ARPMap
}

func New() *ARPScanner {
	a := &ARPScanner{
		State: 0,
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		Timeout: 5 * time.Second,
	}
	gateways := GetGateways()
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, gateway := range gateways {
		gatewayUint32 := IP2Uint32(gateway)
		for _, dev := range devs {
			if dev.Addresses == nil {
				continue
			}
			for _, addr := range dev.Addresses {
				if addr.IP == nil {
					continue
				}
				ipUint32 := IP2Uint32(addr.IP)
				maskUint32 := IPMask2Uint32(addr.Netmask)
				if ipUint32&maskUint32 != gatewayUint32&maskUint32 {
					continue
				}
				for _, i := range ifs {
					if i.Name != dev.Name {
						continue
					}
					handle, err := pcap.OpenLive(i.Name, 1500, false, pcap.BlockForever)
					if err != nil {
						log.Fatal(err)
					}
					arpInterface := ARPInterface{
						Name:    i.Name,
						Gateway: gateway,
						Mask:    maskUint32,
						Handle:  handle,
					}
					a.ARPIfs = append(a.ARPIfs, arpInterface)
				}
			}
		}
	}
	return a
}

func (a *ARPScanner) Close() {
	if a.ARPIfs != nil {
		for _, arpIfs := range a.ARPIfs {
			arpIfs.Handle.Close()
		}
	}
}

func (a *ARPScanner) generateTargets() *[]net.IP {
	var targets []net.IP

	return &targets
}

func (a *ARPScanner) Scan(targets []net.IP) {

}

func (a *ARPScanner) SendARPReq(target net.IP) {
	var targetIp = net.IPv4(192, 168, 48, 1)
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ifs)
	nifs, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	var srcMac net.HardwareAddr
	for _, nif := range nifs {
		if nif.Name == ifs[0].Name {
			srcMac = nif.HardwareAddr
		}
	}
	fmt.Println(srcMac)
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     0x6,
		ProtAddressSize:   0x4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMac,
		SourceProtAddress: ifs[0].Addresses[0].IP.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    targetIp.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, a.Opts, ethLayer, arpLayer)
	if err != nil {
		log.Fatal(err)
	}
	outgoingPacket := buf.Bytes()
	fmt.Println(outgoingPacket)
	err = a.ARPIfs[0].Handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
	// for result := range resultCh {
	// 	fmt.Println(result)
	// 	fmt.Println(targetIp)
	// 	if targetIp.Equal(result.ip) {
	// 		break
	// 	}
	// }
	fmt.Println("done")
}

func main() {
	a := New()
	defer a.Close()
	// oui, err := GetOui()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// resultCh := make(chan ARPScanResult, 10)
	// src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	// packets := src.Packets()
	// a := &ARPScanner{}
	// defer a.Close()
	// targets := a.generateTargets()
	// go a.RecvARP(oui, packets, resultCh)
}

func (a *ARPScanner) RecvARP(oui map[string]string, packets <-chan gopacket.Packet, resultCh chan ARPScanResult) error {
	defer close(resultCh)
	for packet := range packets {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			continue
		}
		srcMac := net.HardwareAddr(arp.SourceHwAddress)
		prefix1, prefix2 := GetOuiPrefix(srcMac)
		vendor := oui[prefix2]
		if len(vendor) == 0 {
			vendor = oui[prefix1]
		}
		resultCh <- ARPScanResult{
			IP:     net.IP(arp.SourceProtAddress),
			Mac:    srcMac,
			Vendor: vendor,
		}
		dstMac := net.HardwareAddr(arp.DstHwAddress)
		prefix1, prefix2 = GetOuiPrefix(dstMac)
		vendor = oui[prefix2]
		if len(vendor) == 0 {
			vendor = oui[prefix1]
		}
		resultCh <- ARPScanResult{
			IP:     net.IP(arp.DstProtAddress),
			Mac:    dstMac,
			Vendor: vendor,
		}
	}
	fmt.Println("recvARP done. ")
	return nil
}
