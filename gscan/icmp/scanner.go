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
		icmpScanner.AScanner.ScanLocalNet()
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
	if icmpScanner.AScanner.ARPIfs != nil {
		//fmt.Println(icmpScanner.AScanner.ARPIfs)
		for _, arpIfs := range icmpScanner.AScanner.ARPIfs {
			handle := common.GetHandle(arpIfs.Name)
			if handle != nil {
				for _, ip := range ipList {
					targetCh <- ICMPTarget{
						Target: arp.Target{
							SrcIP: arpIfs.IP,
							DstIP: ip,
							SrcMac: arpIfs.HWAddr,
							Handle: handle,
						},
						DstMac: icmpScanner.AScanner.AMap[common.IP2Uint32(arpIfs.Gateway)],
					}
				}
			}
		}

	} else {
		log.Fatal("找不到网关对应的网卡")
	}
}

func (icmpScanner *ICMPScanner) ScanList(ipList []net.IP) chan ICMPScanResult {

	fmt.Println("Start Listen To Recv ICMP Packet...")
	resultCh := make(chan ICMPScanResult, 10)
	for _, arpIfs := range icmpScanner.AScanner.ARPIfs {    // 遍历网卡开启监听
		src := gopacket.NewPacketSource(arpIfs.Handle, arpIfs.Handle.LinkType())
		go icmpScanner.RecvICMP(src.Packets(), resultCh)
		fmt.Printf("Open %s Listen...\n", arpIfs.Name)
	}

	fmt.Println("Start Generate TargetChannel By ipList...")
	targetCh := make(chan ICMPTarget, 10)
	go icmpScanner.GenerateTarget(targetCh, ipList)    // 开始生产

	fmt.Println("Start Scan ICMP...")
	go icmpScanner.Scan(targetCh)

	return resultCh
}

func (icmpScanner *ICMPScanner)Scan(targetCh <-chan ICMPTarget) {
	defer close(icmpScanner.Stop)
	for target := range targetCh {
		icmpScanner.SendICMP(target)    // 消费者
	}
	time.Sleep(time.Second*8)   // 等待接收器接受发出去的包
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
			fmt.Println("ICMP Recv Done")
			return
		case packet := <-packets:
			if packet == nil {
				continue
			}

			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}

			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp == nil {
				continue
			}

			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
				icmp.TypeCode.Code() == layers.ICMPv4CodeNet &&
				icmp.Id == constant.ICMPId &&
				icmp.Seq == constant.ICMPSeq {
				//fmt.Println(icmp)
				ip := common.PacketToIPv4(packet)
				if ip != nil {
					resultCh <- ICMPScanResult{ip.To4()}
					fmt.Println("Receive Reply Pakcet from:", ip.To4())
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