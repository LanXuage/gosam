package icmp

import (
	"fmt"
	"gscan/arp"
	"gscan/common"
	"gscan/common/constant"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type ICMPScanner struct {
	Stop     chan struct{}
	AScanner *arp.ARPScanner
	Results  cmap.ConcurrentMap[uint32, bool]
}

type ICMPTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  net.IP           // 发包的源协议IP
	DstIP  net.IP           // 目的IP
	Handle *pcap.Handle     // 发包的具体句柄地址
	DstMac net.HardwareAddr
}

type ICMPScanResult struct {
	IP        net.IP
	IsActive  bool
	IsARPScan bool
}

func New() *ICMPScanner {
	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		AScanner: arp.New(),
		Results:  cmap.NewWithCustomShardingFunction[uint32, bool](func(key uint32) uint32 { return key }),
	}
	return icmpScanner
}

// ICMP发包
func (icmpScanner *ICMPScanner) SendICMP(target ICMPTarget) {
	// 构建以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 构建IP数据包
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    target.SrcIP,
		DstIP:    target.DstIP,
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
	}

	// 构建ICMP数据包
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
		Id:       constant.ICMPId,
		Seq:      constant.ICMPSeq,
	}

	//payload := []byte("Send ICMP by YuSec")
	//icmpLayer.Payload = payload

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

	//fmt.Println(buffer)
	fmt.Println("Ping", target.DstIP)

	err = target.Handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
}

func (icmpScanner *ICMPScanner) GenerateTarget(targetCh chan<- ICMPTarget, ipList []net.IP) {
	defer close(targetCh)
	if icmpScanner.AScanner.Ifaces == nil {
		return
	}
	for _, iface := range *icmpScanner.AScanner.Ifaces {
		if len(ipList) == 0 {
			return
		}
		dstMacAddr, _ := icmpScanner.AScanner.AMap.Get(common.IPv42Uint32(iface.Gateway))
		for _, ip := range ipList {
			targetCh <- ICMPTarget{
				SrcIP:  iface.IP,
				DstIP:  ip,
				SrcMac: iface.HWAddr,
				Handle: iface.Handle,
				DstMac: *dstMacAddr,
			}
		}
	}
}

func (icmpScanner *ICMPScanner) Scan(targetCh <-chan ICMPTarget) {
	defer close(icmpScanner.Stop)

	for target := range targetCh {
		icmpScanner.SendICMP(target)
	}
}

func (ICMPScanner *ICMPScanner) PingLocalNet() {

}

func (icmpScanner *ICMPScanner) ScanList(ipList []net.IP) chan ICMPScanResult {

	resultCh := make(chan ICMPScanResult, 15)

	for i := 0; i < len(ipList); i++ {
		ipUint32 := common.IPv42Uint32(ipList[i])
		if _, ok := icmpScanner.AScanner.AMap.Get(ipUint32); ok {
			icmpScanner.Results.Set(ipUint32, true)
			resultCh <- ICMPScanResult{
				IP:        ipList[i],
				IsActive:  true,
				IsARPScan: true,
			}
			ipList = append(ipList[:i], ipList[(i+1):]...) // 抹除ARP Scanner后的结果, 不计入生产者中
		}
	}

	fmt.Println("Start Generate...")
	targetCh := make(chan ICMPTarget, 10)
	go icmpScanner.GenerateTarget(targetCh, ipList)

	fmt.Println("Start Listen...")
	go icmpScanner.Recv(resultCh)

	fmt.Println("Start ICMP...")
	go icmpScanner.Scan(targetCh)

	go icmpScanner.CheckIPList(ipList)

	return resultCh
}

// 接收协程
func (icmpScanner *ICMPScanner) Recv(resultCh chan<- ICMPScanResult) {
	for r := range common.GetReceiver().Register("icmp", icmpScanner.RecvICMP) {
		if result, ok := r.(ICMPScanResult); ok {
			resultCh <- result
		}
	}
}

// 校验IPLIST
func (icmpScanner *ICMPScanner) CheckIPList(ipList []net.IP) {
	<-icmpScanner.Stop
	for _, ip := range ipList {
		uint32IP := common.IPv42Uint32(ip)
		if _, ok := icmpScanner.Results.Get(uint32IP); !ok {
			icmpScanner.Results.Set(uint32IP, false)
		}
	}
}

// ICMP接包协程
func (icmpScanner *ICMPScanner) RecvICMP(packet gopacket.Packet) interface{} {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return nil
	}
	icmp, _ := icmpLayer.(*layers.ICMPv4)
	if icmp == nil {
		return nil
	}

	if icmp.Id == constant.ICMPId &&
		icmp.Seq == constant.ICMPSeq {
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
			icmp.TypeCode.Code() == layers.ICMPv4CodeNet {
			ip := common.PacketToIPv4(packet)
			if ip != nil {
				icmpScanner.Results.Set(common.IPv42Uint32(ip.To4()), true)
				return ICMPScanResult{
					IP:        ip.To4(),
					IsActive:  true,
					IsARPScan: false,
				}
			}
		}
		if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable {
			ip := common.PacketToIPv4(packet)
			if ip != nil {
				icmpScanner.Results.Set(common.IPv42Uint32(ip.To4()), false)
				fmt.Printf("%s Unreacheable\n", ip.To4())
			}
		}
	}
	return nil
}

func (icmpScanner *ICMPScanner) Close() {
	<-icmpScanner.Stop
}
