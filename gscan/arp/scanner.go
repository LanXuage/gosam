package arp

import (
	"gscan/common"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

const (
	REGISTER_NAME = "ARP"
)

var ETH_BROADCAST = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var ARP_BROADCAST = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

var logger = common.GetLogger()
var receiver = common.GetReceiver()

type ARPScanResult struct {
	IP     netip.Addr       `json:"ip"`     // 结果IP
	Mac    net.HardwareAddr `json:"mac"`    // 结果物理地址
	Vendor string           `json:"vendor"` // 结果物理地址厂商
}

type ARPScanResults struct {
	Results []*ARPScanResult
}

type ARPScanner struct {
	// Deprecated: No longer available.
	Stop    chan struct{}             // ARP 扫描器状态
	Opts    gopacket.SerializeOptions // 包序列化选项
	Timeout time.Duration             // 抓包超时时间
	// Deprecated: Use Ifas instead.
	Ifaces *[]common.GSInterface // 可用接口列表
	Ifas   *[]common.GSIface     // 可用接口列表
	// Deprecated: Use AHMap instead.
	AMap     cmap.ConcurrentMap[uint32, *net.HardwareAddr]    // 获取到的IP <-> Mac 映射表
	AHMap    cmap.ConcurrentMap[netip.Addr, net.HardwareAddr] // 获取到的IP <-> Mac 映射表
	OMap     map[string]string                                // Mac前缀 <-> 厂商 映射表
	Lock     sync.Mutex
	TargetCh chan *Target
	ResultCh chan *ARPScanResult
}

type Target struct {
	SrcMac net.HardwareAddr // 发包的源物理地址
	SrcIP  netip.Addr       // 发包的源协议IP
	DstIP  netip.Addr       // 目的IP
	Handle *pcap.Handle     // 发包的具体句柄地址
}

func newARPScanner() *ARPScanner {
	a := &ARPScanner{
		Stop: make(chan struct{}),
		Opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		Timeout:  3 * time.Second,
		OMap:     common.GetOui(),
		AMap:     cmap.NewWithCustomShardingFunction[uint32, *net.HardwareAddr](func(key uint32) uint32 { return key }),
		AHMap:    cmap.NewWithCustomShardingFunction[netip.Addr, net.HardwareAddr](common.Fnv32),
		Ifaces:   common.GetActiveInterfaces(),
		Ifas:     common.GetActiveIfaces(),
		TargetCh: make(chan *Target, 10),
		ResultCh: make(chan *ARPScanResult, 10),
	}
	go a.Recv()
	go a.Scan()
	for _, iface := range *a.Ifas {
		a.TargetCh <- &Target{
			SrcMac: iface.HWAddr,
			SrcIP:  iface.IP,
			DstIP:  iface.Gateway,
			Handle: iface.Handle,
		}
		for res := range a.ResultCh {
			if iface.Gateway == res.IP {
				break
			}
		}
	}
	return a
}

func (a *ARPScanner) Close() {
	receiver.Unregister(REGISTER_NAME)
	close(a.TargetCh)
	close(a.ResultCh)
}

// 目标生产协程
func (a *ARPScanner) GenerateTarget() {
	for _, iface := range *a.Ifas {
		cIp := iface.Mask.Addr()
		for {
			cIp := cIp.Next()
			if !cIp.IsValid() || !iface.Mask.Contains(cIp) {
				break
			}
			a.TargetCh <- &Target{
				SrcMac: iface.HWAddr,
				SrcIP:  iface.IP,
				DstIP:  cIp,
				Handle: iface.Handle,
			}
		}
	}
}

func (a *ARPScanner) ScanOne(ip netip.Addr) *ARPScanResult {
	for _, iface := range *a.Ifas {
		if iface.Mask.Contains(ip) {
			a.TargetCh <- &Target{
				SrcMac: iface.HWAddr,
				SrcIP:  iface.IP,
				DstIP:  ip,
				Handle: iface.Handle,
			}
			break
		}
	}
	timeoutCh := make(chan struct{})
	go func(timeoutch chan struct{}, timeout time.Duration) {
		time.Sleep(timeout)
		close(timeoutCh)
	}(timeoutCh, a.Timeout)
	for {
		select {
		case result := <-a.ResultCh:
			if result.IP == ip {
				return result
			}
		case <-timeoutCh:
			return nil
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
	for r := range receiver.Register(REGISTER_NAME, a.RecvARP) {
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
		DstMAC:       ETH_BROADCAST,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		HwAddressSize:     0x6,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   target.SrcMac,
		SourceProtAddress: target.SrcIP.AsSlice(),
		DstHwAddress:      ARP_BROADCAST,
		DstProtAddress:    target.DstIP.AsSlice(),
	}
	if target.SrcIP.Is4() {
		arpLayer.ProtAddressSize = 0x4
		arpLayer.Protocol = layers.EthernetTypeIPv4
	} else {
		arpLayer.ProtAddressSize = 0x16
		arpLayer.Protocol = layers.EthernetTypeIPv6
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
	if arp.Operation != layers.ARPReply {
		return result
	}
	srcMac := net.HardwareAddr(arp.SourceHwAddress)
	srcIP, _ := netip.AddrFromSlice(arp.SourceProtAddress)
	if r, ok := a.generateResult(srcIP, srcMac); ok {
		result.Results = append(result.Results, r)
	}
	dstMac := net.HardwareAddr(arp.DstHwAddress)
	dstIP, _ := netip.AddrFromSlice(arp.DstProtAddress)
	if r, ok := a.generateResult(dstIP, dstMac); ok {
		result.Results = append(result.Results, r)
	}
	return result
}

func (a *ARPScanner) generateResult(srcIP netip.Addr, srcMac net.HardwareAddr) (*ARPScanResult, bool) {
	srcIPU32 := common.IP2Uint32(srcIP.AsSlice())
	if _, ok := a.AHMap.Get(srcIP); !ok {
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
		a.AMap.Set(srcIPU32, &srcMac)
		a.AHMap.Set(srcIP, srcMac)
		return result, true
	}
	return nil, false
}

var instance = newARPScanner()

func GetARPScanner() *ARPScanner {
	return instance
}
