package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ARPScanResult struct {
	ip     net.IP
	mac    net.HardwareAddr
	vendor string
}

func getGateWay() net.IP {
	netlinks, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		log.Fatal(err)
	}
	nmsg, err := syscall.ParseNetlinkMessage(netlinks)
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range nmsg {
		if m.Header.Type == syscall.RTM_NEWROUTE {
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				log.Fatal(err)
			}
			for _, attr := range attrs {
				if attr.Attr.Type == syscall.RTA_GATEWAY {
					return attr.Value
				}
			}
		}
	}
	return nil
}

func getOui() (map[string]string, error) {
	ouiFile, err := os.Open("arpscan/ieee-oui.txt")
	if err != nil {
		log.Println("open ieee-oui.txt error ", err)
		return nil, err
	}
	defer ouiFile.Close()
	ouiReader := bufio.NewReader(ouiFile)
	oui := make(map[string]string)
	for {
		line, _, err := ouiReader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		item := strings.Split(string(line), "\t")
		if len(item) != 2 {
			continue
		}
		oui[item[0]] = item[1]
	}
	return oui, nil
}

func arpScan(targets []net.IP) {

}

func main() {
	gateway := getGateWay()
	fmt.Println(gateway)
	oui, err := getOui()
	if err != nil {
		log.Fatal(err)
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	var targetIp = net.IPv4(192, 168, 48, 1)
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ifs)
	handle, err := pcap.OpenLive(ifs[0].Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets := src.Packets()
	resultCh := make(chan ARPScanResult, 10)
	go recvARP(oui, packets, resultCh)
	fmt.Println(handle)
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
	err = gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer)
	if err != nil {
		log.Fatal(err)
	}
	outgoingPacket := buf.Bytes()
	fmt.Println(outgoingPacket)
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
	for result := range resultCh {
		fmt.Println(result)
		fmt.Println(targetIp)
		if targetIp.Equal(result.ip) {
			break
		}
	}
	fmt.Println("done")
}

func recvARP(oui map[string]string, packets <-chan gopacket.Packet, resultCh chan ARPScanResult) error {
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
		prefix1 := strings.ToUpper(strings.Replace(srcMac.String()[:8], ":", "", -1))
		prefix2 := strings.ToUpper(strings.Replace(srcMac.String()[:13], ":", "", -1))
		vendor := oui[prefix2]
		if len(vendor) == 0 {
			vendor = oui[prefix1]
		}
		resultCh <- ARPScanResult{
			ip:     net.IP(arp.SourceProtAddress),
			mac:    srcMac,
			vendor: vendor,
		}
		dstMac := net.HardwareAddr(arp.DstHwAddress)
		prefix1 = strings.ToUpper(strings.Replace(srcMac.String()[:8], ":", "", -1))
		prefix2 = strings.ToUpper(strings.Replace(srcMac.String()[:13], ":", "", -1))
		vendor = oui[prefix2]
		if len(vendor) == 0 {
			vendor = oui[prefix1]
		}
		resultCh <- ARPScanResult{
			ip:     net.IP(arp.DstProtAddress),
			mac:    dstMac,
			vendor: vendor,
		}
	}
	fmt.Println("recvARP done. ")
	return nil
}
