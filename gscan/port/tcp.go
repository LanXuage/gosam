package port

import (
	"gscan/arp"
	"gscan/common"
	"gscan/common/constant"
	"gscan/common/ports"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

var arpInstance = arp.GetARPScanner()

type TCPScanner struct {
	Stop       chan struct{}    // 扫描状态
	IPList     []net.IP         // 扫描的IP列表
	ScanPorts  []layers.TCPPort // 扫描的端口列表
	Results    TCPResultMap     // IP <-> Ports，Port <-> Bool的二维映射
	ResultCh   chan *TCPResult  // 扫描结果Channel
	TargetCh   chan *TCPTarget  // 扫描目标Channel
	HalfSYNRes []TmpTarget      // 存储SYN包的返回结果，用于发送ACK包
	Timeout    time.Duration
	ScanType   uint8
}

type TCPTarget struct {
	SrcIP    net.IP
	SrcPort  layers.TCPPort
	DstIP    net.IP
	DstPorts []layers.TCPPort // 目的端口列表
	Ack      uint32
	SrcMac   net.HardwareAddr
	DstMac   net.HardwareAddr
	Handle   *pcap.Handle
}

// IP <-> Ports，Port <-> Bool的二维映射
type TCPResultMap *cmap.ConcurrentMap[string, *cmap.ConcurrentMap[string, bool]]

type TmpTarget struct {
	IP   net.IP
	Port layers.TCPPort
	Seq  uint32
}

type TCPResult struct {
	IP    net.IP
	Ports map[uint16]bool
}

func NewTCPResultMap() TCPResultMap {
	p := cmap.New[*cmap.ConcurrentMap[string, bool]]()
	return TCPResultMap(&p)
}

func InitialTCPScanner(scanType uint8, ipList []net.IP, scanPorts []layers.TCPPort) *TCPScanner {
	if len(ipList) == 0 || len(scanPorts) == 0 {
		logger.Error("IPList or ScanPorts is NULL, plz check it")
	}

	return &TCPScanner{
		Stop:      make(chan struct{}),
		Results:   NewTCPResultMap(),
		ResultCh:  make(chan *TCPResult, 10),
		TargetCh:  make(chan *TCPTarget, 10),
		Timeout:   time.Second * 3,
		ScanType:  scanType,
		IPList:    ipList,
		ScanPorts: scanPorts,
	}
}

func (t *TCPScanner) GenerateTarget() {

	defer close(t.TargetCh)
	ifaces := common.GetActiveInterfaces()

	if ifaces == nil || len(t.IPList) == 0 {
		return
	}

	for _, iface := range *ifaces {
		gatewayMac := *arpInstance.AMap[common.IP2Uint32(iface.Gateway)]
		for _, ip := range t.IPList {
			tmp := &TCPTarget{
				SrcIP:    iface.IP,
				SrcPort:  layers.TCPPort(ports.DEFAULT_SOURCEPORT),
				DstIP:    ip,
				DstPorts: t.ScanPorts,
				SrcMac:   iface.HWAddr,
				DstMac:   gatewayMac,
				Ack:      0,
				Handle:   iface.Handle,
			}
			t.TargetCh <- tmp
		}
	}

	time.Sleep(t.Timeout)
}

func (t *TCPScanner) Scan() {
	defer close(t.Stop)
	for target := range t.TargetCh {
		t.SendSYNTCP(target)
	}
}

// 发送SYN包
func (t *TCPScanner) SendSYNTCP(target *TCPTarget) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// 以太层
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// ip层
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    target.SrcIP,
		DstIP:    target.DstIP,
		Flags:    layers.IPv4DontFragment,
	}

	for _, port := range target.DstPorts {
		// tcp层
		tcpLayer := &layers.TCP{
			SrcPort: target.SrcPort,
			DstPort: layers.TCPPort(port),
			Seq:     100,
			SYN:     true,
			Options: []layers.TCPOption{},
		}
		if target.Ack != 0 {
			tcpLayer.Ack = target.Ack
			tcpLayer.ACK = true
			tcpLayer.SYN = false
		}

		tcpLayer.SetNetworkLayerForChecksum(ipLayer)

		err := gopacket.SerializeLayers(
			buffer,
			opts,
			ethLayer,
			ipLayer,
			tcpLayer,
		)

		if err != nil {
			logger.Error("SerializeLayers Failed", zap.Error(err))
		}

		err = target.Handle.WritePacketData(buffer.Bytes())

		if err != nil {
			logger.Error("WritePacketData Failed", zap.Error(err))
		}
	}
}

func (t *TCPScanner) Recv() {
	defer close(t.ResultCh)
	for r := range common.GetReceiver().Register(constant.TCPREGISTER_NAME, t.RecvTCP) {
		if result, ok := r.(*TCPResult); ok {
			t.ResultCh <- result
		}
	}
}

func (t *TCPScanner) RecvTCP(packet gopacket.Packet) interface{} {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}

	eth := ethLayer.(*layers.Ethernet)
	if eth == nil {
		return nil
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip := ipLayer.(*layers.IPv4)
	if ip == nil {
		return nil
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp == nil {
		return nil
	}

	if tcp.DstPort == layers.TCPPort(ports.DEFAULT_SOURCEPORT) {

		// logger.Sugar().Debugf("Receive From %s's Port %d\n", ip.SrcIP, tcp.SrcPort)
		if tcp.SYN && t.ScanType == constant.TYPE_FULLTCP { // 第一次收到的包，并且扫描方式为SYN全连接
			dstPort := []layers.TCPPort{}
			dstPort = append(dstPort, tcp.SrcPort)

			tmp2 := &TCPTarget{
				SrcIP:    ip.DstIP,
				SrcPort:  layers.TCPPort(ports.DEFAULT_SOURCEPORT),
				DstIP:    ip.SrcIP,
				DstPorts: dstPort,
				SrcMac:   eth.DstMAC,
				DstMac:   eth.SrcMAC,
				Ack:      tcp.Seq + 1,
				Handle:   common.GetInterfaceBySrcMac(eth.DstMAC).Handle,
			}
			t.TargetCh <- tmp2
			return nil
		}

		// 此处为SYN半连接扫描收到响应包后，或者SYN全连接扫描收到第二个响应包后 写入结果
		if res, ok := (*t.Results).Get(ip.SrcIP.String()); res == nil && !ok {
			// 初始化Port <-> Bool的映射
			tmpMap := cmap.New[bool]()
			(*t.Results).Set(ip.SrcIP.String(), &tmpMap)
		}

		if res, ok := (*t.Results).Get(ip.SrcIP.String()); res != nil && ok {
			// 写入映射
			res.Set(tcp.SrcPort.String(), true)
			logger.Sugar().Debugf("IP: %s, Port: %s, Status: true", ip.SrcIP, tcp.SrcPort)
		}

		return TCPResult{
			IP: ip.SrcIP,
			Ports: map[uint16]bool{
				uint16(tcp.SrcPort): true,
			},
		}

	}
	return nil
}

func (t *TCPScanner) CheckIPList() {
	<-t.Stop
	for _, ip := range t.IPList {
		// 判断IP是否存在，如不存在，则需要初始化cmap.ConcurrentMap[string, bool] 即Port<->Bool的映射
		if res, _ := (*t.Results).Get(ip.String()); res == nil {
			tmpMap := cmap.New[bool]()
			(*t.Results).Set(ip.String(), &tmpMap)
		}

		if res, ok := (*t.Results).Get(ip.String()); res != nil && ok {
			for _, port := range t.ScanPorts {
				if portStatus, ok := res.Get(port.String()); ok && portStatus {
					continue
				}
				res.Set(port.String(), false)
			}
		}
	}
}

func (t *TCPScanner) Close() {
	<-t.Stop
}
