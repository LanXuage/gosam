package arp

import (
	"gscan/common"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

var logger = common.GetLogger()

type ARPScanResult struct {
	IP     net.IP           // 结果IP
	Mac    net.HardwareAddr // 结果物理地址
	Vendor string           // 结果物理地址厂商
}

type ARPScanResults struct {
	Results []*ARPScanResult
}

type ARPMap map[uint32]*net.HardwareAddr // IP <-> Mac 映射表类型
type OUIMap map[string]string            // Mac前缀 <-> 厂商 映射表类型

type ARPScanner struct {
	Stop     chan struct{}             // ARP 扫描器状态
	Opts     gopacket.SerializeOptions // 包序列化选项
	Timeout  time.Duration             // 抓包超时时间
	Ifaces   *[]common.GSInterface     // 可用接口列表
	AMap     ARPMap                    // 获取到的IP <-> Mac 映射表
	OMap     OUIMap                    // Mac前缀 <-> 厂商 映射表
	Lock     sync.Mutex
	TargetCh chan *Target
	ResultCh chan *ARPScanResult
}

type Target struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  net.IP           // 发包的源协议IP
	DstIP  net.IP           // 目的IP
	Handle *pcap.Handle     // 发包的具体句柄地址
}

func New() *ARPScanner {
	a := &ARPScanner{
		Stop: make(chan struct{}),
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		Timeout:  3 * time.Second,
		OMap:     common.GetOui(),
		AMap:     make(ARPMap),
		Ifaces:   common.GetActiveInterfaces(),
		TargetCh: make(chan *Target, 10),
		ResultCh: make(chan *ARPScanResult, 10),
	}
	go a.Recv()
	go a.Scan()
	for _, iface := range *a.Ifaces {
		a.TargetCh <- &Target{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  iface.Gateway,
			Handle: iface.Handle,
		}
		for res := range a.ResultCh {
			if iface.Gateway.Equal(res.IP) {
				break
			}
		}
	}
	return a
}

func (a *ARPScanner) Close() {
	common.GetReceiver().Unregister("arp")
	close(a.TargetCh)
	close(a.ResultCh)
}

// 目标生产协程
func (a *ARPScanner) GenerateTarget() {
	for _, iface := range *a.Ifaces {
		ipU32 := common.IP2Uint32(iface.IP)
		start := iface.Mask & ipU32
		for i := start + 1; i < start+^iface.Mask; i++ {
			a.TargetCh <- &Target{
				SrcMac: iface.HWAddr,
				SrcIP:  iface.IP,
				DstIP:  common.Uint322IP(i),
				Handle: iface.Handle,
			}
		}
	}
}

// 执行全局域网扫描
func (a *ARPScanner) ScanLocalNet() chan *ARPScanResult {
	logger.Debug("Start Generate")
	// logger.Sync()
	go a.GenerateTarget()
	return a.ResultCh
}

// 接收协程
func (a *ARPScanner) Recv() {
	defer close(a.ResultCh)
	for r := range common.GetReceiver().Register("arp", a.RecvARP) {
		if results, ok := r.(ARPScanResults); ok {
			for _, result := range results.Results {
				a.ResultCh <- result
			}
		}
	}
}

// 扫描协程
func (a *ARPScanner) Scan() {
	defer close(a.Stop)
	for target := range a.TargetCh {
		a.SendARPReq(target)
	}
}

// ARP发包
func (a *ARPScanner) SendARPReq(target *Target) {
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
		logger.Error("SerializeLayers Failed", zap.Error(err))
	}
	outgoingPacket := buf.Bytes()
	err = target.Handle.WritePacketData(outgoingPacket)
	if err != nil {
		logger.Error("WritePacketData Failed", zap.Error(err))
	}
}

// 接收协程
func (a *ARPScanner) RecvARP(packet gopacket.Packet) interface{} {
	result := ARPScanResults{
		Results: make([]*ARPScanResult, 0),
	}
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return result
	}
	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return result
	}
	srcMac := net.HardwareAddr(arp.SourceHwAddress)
	srcIP := net.IP(arp.SourceProtAddress)
	if r, ok := a.generateResult(srcIP, srcMac); ok {
		result.Results = append(result.Results, r)
	}
	dstMac := net.HardwareAddr(arp.DstHwAddress)
	dstIP := net.IP(arp.DstProtAddress)
	if r, ok := a.generateResult(dstIP, dstMac); ok {
		result.Results = append(result.Results, r)
	}
	return result
}

func (a *ARPScanner) generateResult(srcIP net.IP, srcMac net.HardwareAddr) (*ARPScanResult, bool) {
	srcIPU32 := common.IP2Uint32(srcIP)
	a.Lock.Lock()
	defer a.Lock.Unlock()
	if a.AMap[srcIPU32] == nil {
		prefix1, prefix2 := common.GetOuiPrefix(srcMac)
		vendor := a.OMap[prefix2]
		if len(vendor) == 0 {
			vendor = a.OMap[prefix1]
		}
		result := &ARPScanResult{
			IP:     srcIP,
			Mac:    srcMac,
			Vendor: vendor,
		}
		a.AMap[srcIPU32] = &srcMac
		return result, true
	}
	return nil, false
}
