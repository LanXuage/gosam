package icmp

import (
	"gscan/arp"
	"gscan/common"
	"gscan/common/constant"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

var arpInstance = arp.GetARPScanner()
var logger = common.GetLogger()

type ICMPScanner struct {
	Stop     chan struct{}        // 发包结束的信号
	Results  ICMPResultMap        // 存放本次扫描结果
	TargetCh chan *ICMPTarget     // 暂存单个所需扫描的IP
	ResultCh chan *ICMPScanResult // 暂存单个IP扫描结果
	IPList   []netip.Addr         // 存放本次所需扫描的IP
	Timeout  time.Duration        // 默认超时时间
}

type ICMPTarget struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  netip.Addr       // 发包的源协议IP
	DstIP  netip.Addr       // 目的IP
	DstMac net.HardwareAddr // 目的Mac
	Handle *pcap.Handle     // 发包的具体句柄地址
}

type ICMPScanResult struct {
	IP       netip.Addr
	IsActive bool // 是否存活
}

type ICMPResultMap *cmap.ConcurrentMap[string, bool]

func New() *ICMPScanner {
	_rMap := cmap.New[bool]()
	rMap := ICMPResultMap(&_rMap)

	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		TargetCh: make(chan *ICMPTarget, constant.CHANNEL_SIZE),
		ResultCh: make(chan *ICMPScanResult, constant.CHANNEL_SIZE),
		Results:  rMap,
		IPList:   []netip.Addr{},
		Timeout:  time.Second * 3,
	}
	return icmpScanner
}

func (icmpScanner *ICMPScanner) Close() {
	common.GetReceiver().Unregister(constant.ICMPREGISTER_NAME)
	close(icmpScanner.ResultCh)
}

// ICMP发包
func (icmpScanner *ICMPScanner) SendICMP(target *ICMPTarget) {
	payload := []byte("ping by gscan") // 特征
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// 构建以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC: target.SrcMac,
		DstMAC: target.DstMac,
	}

	if target.SrcIP.Is4() {
		ethLayer.EthernetType = layers.EthernetTypeIPv4
		ipLayer := &layers.IPv4{
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    target.SrcIP.AsSlice(),
			DstIP:    target.DstIP.AsSlice(),
			Version:  4,
			Flags:    layers.IPv4DontFragment,
			TTL:      64,
		}

		icmpLayer := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
			Id:       constant.ICMPId,
			Seq:      constant.ICMPSeq,
		}

		// 合并数据包并进行序列化
		err := gopacket.SerializeLayers(
			buffer,
			opts,
			ethLayer,
			ipLayer,
			icmpLayer,
			gopacket.Payload(payload),
		)

		if err != nil {
			logger.Error("Combine Buffer Error", zap.Error(err))
		}

		logger.Sugar().Debugf("Ping IP: %s", target.DstIP.String())

		err = target.Handle.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Fatal(err)
		}

	} else {
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

}

func (icmpScanner *ICMPScanner) generateTargetByIPList() {
	defer close(icmpScanner.TargetCh)
	if arpInstance.Ifaces == nil {
		logger.Fatal("Get Ifaces Failed")
		return
	}

	if len(icmpScanner.IPList) == 0 {
		logger.Fatal("IPList is NULL")
		return
	}

	for _, iface := range *arpInstance.Ifas {
		if dstMac, ok := arpInstance.AHMap.Get(iface.Gateway); ok {
			for _, ip := range icmpScanner.IPList {
				icmpScanner.TargetCh <- &ICMPTarget{
					SrcIP:  iface.IP,
					DstIP:  ip,
					SrcMac: iface.HWAddr,
					Handle: iface.Handle,
					DstMac: dstMac,
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
	time.Sleep(icmpScanner.Timeout)
}

func (icmpScanner *ICMPScanner) ScanList(ipList []netip.Addr) chan struct{} {
	icmpScanner.IPList = ipList

	timeoutCh := make(chan struct{})
	// icmpScanner.filterIPList()

	go icmpScanner.Recv()
	go icmpScanner.Scan()

	go icmpScanner.generateTargetByIPList()
	go icmpScanner.CheckIPList()

	time.Sleep(icmpScanner.Timeout)
	return timeoutCh
}

func (icmpScanner *ICMPScanner) ScanOne(ip netip.Addr) chan struct{} {

	icmpScanner.IPList = append(icmpScanner.IPList, ip)
	timeoutCh := make(chan struct{})

	go icmpScanner.Recv()
	go icmpScanner.Scan()

	go icmpScanner.generateTargetByIPList()
	go icmpScanner.CheckIPList()

	time.Sleep(icmpScanner.Timeout)
	return timeoutCh
}

// CIDR Scanner
func (icmpScanner *ICMPScanner) ScanListByPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})

	logger.Debug("启动监听和扫描")
	go icmpScanner.Recv()
	go icmpScanner.Scan()

	logger.Debug("开始生成扫描目标")
	go icmpScanner.goGenerateTargetPrefix(prefix)

	logger.Debug("开始校验扫描结果")
	go icmpScanner.CheckIPList()

	time.Sleep(icmpScanner.Timeout)
	return timeoutCh
}

func (icmpScanner *ICMPScanner) goGenerateTargetPrefix(prefix netip.Prefix) {
	for _, iface := range *arpInstance.Ifas {
		icmpScanner.generateTargetByPrefix(prefix, iface)
	}
}

func (icmpScanner *ICMPScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface) {
	defer close(icmpScanner.TargetCh)
	nIP := prefix.Addr()
	for {
		if nIP.IsValid() && prefix.Contains(nIP) {
			if dstMac, ok := arpInstance.AHMap.Get(iface.Gateway); ok {
				icmpScanner.TargetCh <- &ICMPTarget{
					SrcIP:  iface.IP,
					DstIP:  nIP,
					SrcMac: iface.HWAddr,
					Handle: iface.Handle,
					DstMac: dstMac,
				}
			}

			icmpScanner.IPList = append(icmpScanner.IPList, nIP)
			nIP = nIP.Next()
		} else {
			break
		}
	}
}

func (icmpScanner *ICMPScanner) filterIPList() {
	for i := 0; i < len(icmpScanner.IPList); i++ {
		if _, ok := arpInstance.AHMap.Get(icmpScanner.IPList[i]); ok {
			(*icmpScanner.Results).Set(icmpScanner.IPList[i].String(), true)
			icmpScanner.ResultCh <- &ICMPScanResult{
				IP:       icmpScanner.IPList[i],
				IsActive: true,
			}
			icmpScanner.IPList = append(icmpScanner.IPList[:i], icmpScanner.IPList[(i+1):]...) // 抹除ARP Scanner后的结果, 不计入生产者中
		}
	}
}

// 接收协程
func (icmpScanner *ICMPScanner) Recv() {
	for r := range common.GetReceiver().Register(constant.ICMPREGISTER_NAME, icmpScanner.RecvICMP) {
		if result, ok := r.(ICMPScanResult); ok {
			icmpScanner.ResultCh <- &result
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
				if _, ok := (*icmpScanner.Results).Get(ip.To4().String()); !ok {
					(*icmpScanner.Results).Set(ip.To4().String(), true)
					return ICMPScanResult{
						IP:       netip.AddrFrom4([4]byte(ip)),
						IsActive: true,
					}
				}
			}
		}
	}
	return nil
}

// 校验IPLIST
func (icmpScanner *ICMPScanner) CheckIPList() {
	// defer close(icmpScanner.ResultCh)

	<-icmpScanner.Stop
	for _, ip := range icmpScanner.IPList {
		if _, ok := (*icmpScanner.Results).Get(ip.String()); !ok {
			// 该IP未进扫描结果，此时发包结束，并且经过一定时间的延时，未收到返回包，说明并未Ping通
			icmpScanner.ResultCh <- &ICMPScanResult{
				IP:       ip,
				IsActive: false,
			}
			(*icmpScanner.Results).Set(ip.String(), false)
		}
	}
}
