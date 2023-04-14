package port

import (
	"gscan/arp"
	"gscan/common"
	"gscan/common/ports"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

var arpInstance = arp.GetARPScanner()

const (
	TYPE_FULLTCP uint8 = 1
	TYPE_HALFTCP uint8 = 2
)

type TCPScanner struct {
	Stop       chan struct{}                      // 扫描状态
	IPList     []net.IP                           // 扫描的IP列表
	ScanPorts  []layers.TCPPort                   // 扫描的端口列表
	Results    map[uint32]map[layers.TCPPort]bool // IP <-> Ports，Port <-> Bool的二维映射
	ResultCh   chan *TCPResult                    // 扫描结果Channel
	TargetCh   chan *TCPTarget                    // 扫描目标Channel
	HalfSYNRes []TmpTarget                        // 存储SYN包的返回结果，用于发送ACK包
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

type TmpTarget struct {
	IP   net.IP
	Port layers.TCPPort
	Seq  uint32
}

type TCPResult struct {
	IP    net.IP
	Ports map[uint16]bool
}

func InitialTCPScanner(scanType uint8, ipList []net.IP, scanPorts []layers.TCPPort) *TCPScanner {
	if len(ipList) == 0 || len(scanPorts) == 0 {
		logger.Error("IPList or ScanPorts is NULL")
	}

	return &TCPScanner{
		Stop:      make(chan struct{}),
		Results:   make(map[uint32]map[layers.TCPPort]bool),
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
		logger.Sugar().Debugf("%d", common.IP2Uint32(iface.Gateway))
		gatewayMac := *arpInstance.AMap[common.IP2Uint32(iface.Gateway)]
		if gatewayMac.String() == "00:00:00:00:00:00" {
			logger.Fatal("Get Gateway Mac Address Failed")
		}
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
	for r := range common.GetReceiver().Register("tcp", t.RecvTCP) {
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

		logger.Sugar().Infof("Receive From %s's Port %d\n", ip.SrcIP, tcp.SrcPort)

		if tcp.SYN && t.ScanType == TYPE_FULLTCP { // 第一次收到的包
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

		uint32IP := common.IP2Uint32(ip.SrcIP)
		if t.Results[uint32IP] == nil {
			t.Results[uint32IP] = make(map[layers.TCPPort]bool)
		}

		t.Results[uint32IP][tcp.SrcPort] = true

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
		uint32IP := common.IP2Uint32(ip)
		if t.Results[uint32IP] == nil {
			t.Results[uint32IP] = make(map[layers.TCPPort]bool)
			for _, port := range t.ScanPorts {
				t.Results[uint32IP][port] = false
			}
		} else {
			for _, port := range t.ScanPorts {
				if !t.Results[uint32IP][port] {
					t.Results[uint32IP][port] = false
				}
			}
		}

	}
}
