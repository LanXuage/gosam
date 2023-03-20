package icmp

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gscan/arp"
	"gscan/common"
	"gscan/common/constant"
	"log"
	"net"
	"time"
)

type ICMPScanner struct {
	Stop     chan struct{}
	AScanner *arp.ARPScanner
}

type ICMPTarget struct {
	arp.Target
	DstMac	net.HardwareAddr
}


type ICMPScanResult struct {
	IP net.IP
}

func New() *ICMPScanner {
	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		AScanner: arp.New(),
	}
	go func() {
		for result := range icmpScanner.AScanner.ScanLocalNet() {
			fmt.Println(result)
		}
	}()

	<-icmpScanner.AScanner.GotGateway
	//uint32IP := common.IP2Uint32(icmpScanner.AScanner.ARPIfs[0].Gateway)
	//fmt.Println(uint32IP)
	//if icmpScanner.AScanner.AMap[uint32IP] != nil {
	//	fmt.Println(icmpScanner.AScanner.AMap[uint32IP])
	//} else {
	//	fmt.Println("fuck")
	//}

	return icmpScanner
}

func (icmpScanner *ICMPScanner) GenerateTarget(targetCh chan<- ICMPTarget, ipList []net.IP) {
	defer close(targetCh)
	for _, ip := range ipList {
		targetCh <- ICMPTarget{
			Target: arp.Target{
				SrcIP: icmpScanner.AScanner.ARPIfs[0].IP,
				DstIP: ip,
				SrcMac: icmpScanner.AScanner.ARPIfs[0].HWAddr,
				Handle: icmpScanner.AScanner.ARPIfs[0].Handle,
			},
			DstMac: icmpScanner.AScanner.AMap[common.IP2Uint32(icmpScanner.AScanner.ARPIfs[0].Gateway)],
		}
	}
}

func (icmpScanner *ICMPScanner) Scan(ipList []net.IP) chan ICMPScanResult {
	targetCh := make(chan ICMPTarget, 10)
	fmt.Println("Start Generate")
	go icmpScanner.GenerateTarget(targetCh, ipList)
	resultCh := make(chan ICMPScanResult, 10)
	fmt.Println("Start Recv")
	for _, arpIfs := range icmpScanner.AScanner.ARPIfs {
		src := gopacket.NewPacketSource(arpIfs.Handle, arpIfs.Handle.LinkType())
		go icmpScanner.RecvICMP(src.Packets(), resultCh)
	}
	fmt.Println("Start Scan")

	go func() {
		//defer close(icmpScanner.Stop)
		for target := range targetCh {
			icmpScanner.SendICMP(target)
		}
		time.Sleep(time.Second*5)
	}()
	return resultCh
}

func (icmpScanner *ICMPScanner) SendICMP(target ICMPTarget) {
	// 构建以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC: target.SrcMac,
		DstMAC: target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 构建IP数据包
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolICMPv4,
		SrcIP: target.SrcIP,
		DstIP: target.DstIP,
		Version: 4,
		Flags: layers.IPv4DontFragment,
		TTL: 54,
	}

	// 构建ICMP数据包
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
		Id:       constant.ICMPId,
		Seq:      constant.ICMPSeq,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// 合并数据包并进行序列化
	err := gopacket.SerializeLayers(
		buffer,
		opts,
		ethLayer,
		ipLayer,
		icmpLayer,
	)

	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(buffer.Bytes())
	fmt.Println("Sent ICMP Echo Request To", target.DstIP)

	err = target.Handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
}

func (icmpScanner *ICMPScanner) RecvICMP(packets <-chan gopacket.Packet, resultCh chan<- ICMPScanResult) {
	defer close(resultCh)
	for {
		select {
		case <-icmpScanner.Stop:
			fmt.Println("fuck")
			return
		case packet := <-packets:
			//fmt.Println(packet)
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				fmt.Println(icmp.Id, icmp.Seq)
				if icmp.Id == constant.ICMPId && icmp.Seq == constant.ICMPSeq {
					if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
						icmp.TypeCode.Code() == layers.ICMPv4CodeNet {
						ip := common.PacketToIPv4(packet)
						if ip != nil {
							resultCh <- ICMPScanResult{ip.To4()}
							fmt.Println("Receive Reply Pakcet from:", ip.To4())
						}
					}
				}
			}
		}
	}
}

func (icmpScanner *ICMPScanner) Close() {
	if icmpScanner.AScanner != nil {
		icmpScanner.AScanner.Close()
	}
}
