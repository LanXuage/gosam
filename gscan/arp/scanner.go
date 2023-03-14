package arpscan

import (
	"fmt"
	"gscan/common"
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
	HWAddr  net.HardwareAddr
	IP      net.IP
	Handle  *pcap.Handle
}

type ARPScanResult struct {
	IP     net.IP
	Mac    net.HardwareAddr
	Vendor string
}

type ARPMap map[uint32]net.HardwareAddr
type OUIMap map[string]string

type ARPScanner struct {
	State   int8
	Opts    gopacket.SerializeOptions
	Timeout time.Duration
	ARPIfs  []ARPInterface
	AMap    ARPMap
	OMap    OUIMap
}

type Target struct {
	SrcMac net.HardwareAddr
	SrcIP  net.IP
	DstIP  net.IP
	Handle *pcap.Handle
}

func New() *ARPScanner {
	omap, err := common.GetOui()
	if err != nil {
		log.Fatal(err)
	}
	a := &ARPScanner{
		State: 0,
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		Timeout: 5 * time.Second,
		OMap:    omap,
		AMap:    make(ARPMap),
	}
	gateways := common.GetGateways()
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, gateway := range gateways {
		gatewayUint32 := common.IP2Uint32(gateway)
		for _, dev := range devs {
			if dev.Addresses == nil {
				continue
			}
			for _, addr := range dev.Addresses {
				if addr.IP == nil {
					continue
				}
				ipUint32 := common.IP2Uint32(addr.IP)
				maskUint32 := common.IPMask2Uint32(addr.Netmask)
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
						HWAddr:  i.HardwareAddr,
						IP:      addr.IP,
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

func (a *ARPScanner) GenerateTarget(targetCh chan<- Target) {
	for _, arpIfs := range a.ARPIfs {
		ipU32 := common.IP2Uint32(arpIfs.IP)
		start := arpIfs.Mask & ipU32
		for i := start + 1; i < start+^arpIfs.Mask; i++ {
			targetCh <- Target{
				SrcMac: arpIfs.HWAddr,
				SrcIP:  arpIfs.IP,
				DstIP:  common.Uint322IP(i),
				Handle: arpIfs.Handle,
			}
		}
	}
}

func (a *ARPScanner) ScanLocalNet() <-chan ARPScanResult {
	targetCh := make(chan Target, 10)
	fmt.Println("Start Generate")
	go a.GenerateTarget(targetCh)
	resultCh := make(chan ARPScanResult, 10)
	fmt.Println("Start Recv")
	for _, arpIfs := range a.ARPIfs {
		src := gopacket.NewPacketSource(arpIfs.Handle, layers.LayerTypeEthernet)
		go a.RecvARP(src.Packets(), resultCh)
	}
	fmt.Println("Start Scan")
	go a.Scan(targetCh)
	return resultCh
}

func (a *ARPScanner) Scan(targetCh <-chan Target) {
	for target := range targetCh {
		a.SendARPReq(target)
	}
}

func (a *ARPScanner) SendARPReq(target Target) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     0x6,
		ProtAddressSize:   0x4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   target.SrcMac,
		SourceProtAddress: target.SrcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    target.DstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, a.Opts, ethLayer, arpLayer)
	if err != nil {
		log.Fatal(err)
	}
	outgoingPacket := buf.Bytes()
	err = target.Handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}

func (a *ARPScanner) RecvARP(packets <-chan gopacket.Packet, resultCh chan<- ARPScanResult) error {
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
		srcIP := net.IP(arp.SourceProtAddress)
		srcIPU32 := common.IP2Uint32(srcIP)
		if a.AMap[srcIPU32] == nil {
			prefix1, prefix2 := common.GetOuiPrefix(srcMac)
			vendor := a.OMap[prefix2]
			if len(vendor) == 0 {
				vendor = a.OMap[prefix1]
			}
			resultCh <- ARPScanResult{
				IP:     srcIP,
				Mac:    srcMac,
				Vendor: vendor,
			}
			a.AMap[srcIPU32] = srcMac
		}
		dstMac := net.HardwareAddr(arp.DstHwAddress)
		dstIP := net.IP(arp.DstProtAddress)
		dstIPU32 := common.IP2Uint32(dstIP)
		if a.AMap[common.IP2Uint32(srcIP)] == nil {
			prefix1, prefix2 := common.GetOuiPrefix(dstMac)
			vendor := a.OMap[prefix2]
			if len(vendor) == 0 {
				vendor = a.OMap[prefix1]
			}
			resultCh <- ARPScanResult{
				IP:     dstIP,
				Mac:    dstMac,
				Vendor: vendor,
			}
			a.AMap[dstIPU32] = dstMac
		}
	}
	fmt.Println("recvARP done. ")
	return nil
}

func test() {
	a := New()
	defer a.Close()
	for result := range a.ScanLocalNet() {
		fmt.Println(result)
	}
}
