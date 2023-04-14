package icmp

import (
	"gscan/arp"
	"gscan/common"
	"gscan/common/constant"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

const (
	REGISTER_NAME string = "icmp"
)

var arpInstance = arp.GetARPScanner()
var logger = common.GetLogger()

type ICMPScanner struct {
	Stop     chan struct{}
	Results  ICMPResultMap
	TargetCh chan *ICMPTarget
	Timeout  time.Duration
}

type ICMPTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  net.IP           // 发包的源协议IP
	DstIP  net.IP           // 目的IP
	DstMac net.HardwareAddr // 目的Mac
	Handle *pcap.Handle     // 发包的具体句柄地址
}

type ICMPScanResult struct {
	IP        net.IP
	IsActive  bool
	IsARPScan bool
}

type ICMPResultMap map[uint32]bool

func New() *ICMPScanner {
	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		Results:  make(ICMPResultMap),
		TargetCh: make(chan *ICMPTarget, 10),
		Timeout:  time.Second * 5,
	}
	return icmpScanner
}

// ICMP发包
func (icmpScanner *ICMPScanner) SendICMP(target *ICMPTarget) {
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
		logger.Error("Combine Buffer Error", zap.Error(err))
	}

	logger.Sugar().Infof("Ping IP: %s", target.DstIP.String())

	err = target.Handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
}

func (icmpScanner *ICMPScanner) GenerateTarget(ipList []net.IP) {
	defer close(icmpScanner.TargetCh)
	if arpInstance.Ifaces == nil {
		logger.Fatal("Get Ifaces Failed")
		return
	}

	if len(ipList) == 0 {
		logger.Fatal("IPList is NULL")
		return
	}

	for _, iface := range *arpInstance.Ifaces {
		if *arpInstance.AMap[common.IP2Uint32(iface.Gateway)] != nil {

			for _, ip := range ipList {
				icmpScanner.TargetCh <- &ICMPTarget{
					SrcIP:  iface.IP,
					DstIP:  ip,
					SrcMac: iface.HWAddr,
					Handle: iface.Handle,
					DstMac: *arpInstance.AMap[common.IP2Uint32(iface.Gateway)],
				}
			}
		}

	}
}

func (icmpScanner *ICMPScanner) Scan() {
	defer close(icmpScanner.Stop)
	for target := range icmpScanner.TargetCh {
		icmpScanner.SendICMP(target)
	}
}

func (icmpScanner *ICMPScanner) ScanList(ipList []net.IP) chan ICMPScanResult {

	resultCh := make(chan ICMPScanResult, 15)

	for i := 0; i < len(ipList); i++ {
		ipUint32 := common.IP2Uint32(ipList[i])
		if arpInstance.AMap[ipUint32] != nil {
			icmpScanner.Results[ipUint32] = true
			resultCh <- ICMPScanResult{
				IP:        ipList[i],
				IsActive:  true,
				IsARPScan: true,
			}
			ipList = append(ipList[:i], ipList[(i+1):]...) // 抹除ARP Scanner后的结果, 不计入生产者中
		}
	}

	logger.Debug("Start Generate...")
	go icmpScanner.GenerateTarget(ipList)

	logger.Debug("Start Listen...")
	go icmpScanner.Recv(resultCh)

	logger.Debug("Start ICMP...")
	go icmpScanner.Scan()

	go icmpScanner.CheckIPList(ipList)

	return resultCh
}

// 接收协程
func (icmpScanner *ICMPScanner) Recv(resultCh chan<- ICMPScanResult) {
	for r := range common.GetReceiver().Register(REGISTER_NAME, icmpScanner.RecvICMP) {
		if result, ok := r.(ICMPScanResult); ok {
			resultCh <- result
		}
	}
}

// 校验IPLIST
func (icmpScanner *ICMPScanner) CheckIPList(ipList []net.IP) {
	<-icmpScanner.Stop
	for _, ip := range ipList {
		uint32IP := common.IP2Uint32(ip)
		if !icmpScanner.Results[uint32IP] {
			icmpScanner.Results[uint32IP] = false
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
				icmpScanner.Results[common.IP2Uint32(ip.To4())] = true
				return ICMPScanResult{
					IP:        ip.To4(),
					IsActive:  true,
					IsARPScan: false,
				}
			}
		}
		// if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable {
		// 	ip := common.PacketToIPv4(packet)
		// 	if ip != nil {
		// 		icmpScanner.Results[common.IP2Uint32(ip.To4())] = false
		// 		logger.Sugar().Infof("%s Unreacheable\n", ip.To4())
		// 	}
		// }
	}
	return nil
}

func (icmpScanner *ICMPScanner) Close() {
	common.GetReceiver().Unregister(REGISTER_NAME)
}
