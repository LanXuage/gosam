package port

import (
	"fmt"
	"gscan/arp"
	"gscan/common"
	"gscan/common/ports"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arpInstance = arp.GetARPScanner()

type TCPScanner struct {
	Stop     chan struct{}              // 扫描状态
	Results  map[uint32]map[uint16]bool // IP <-> Ports，Port <-> Bool的二维映射
	ResultCh chan *TCPResult            // 扫描结果Channel
	TargetCh chan *TCPTarget            // 扫描目标Channel
}

type TCPTarget struct {
	SrcIP    net.IP
	SrcPort  layers.TCPPort
	DstIP    net.IP
	DstPorts []layers.TCPPort // 目的端口列表
	SrcMac   net.HardwareAddr
	DstMac   net.HardwareAddr
	Handle   *pcap.Handle
}

type TCPResult struct {
	IP    net.IP
	Ports map[uint16]bool
}

func InitialTCPScanner() *TCPScanner {
	return &TCPScanner{
		Stop:     make(chan struct{}),
		Results:  make(map[uint32]map[uint16]bool),
		ResultCh: make(chan *TCPResult, 10),
		TargetCh: make(chan *TCPTarget, 10),
	}
}

func (t *TCPScanner) GenerateTarget(ipList []net.IP) {

	defer close(t.TargetCh)
	ifaces := common.GetActiveInterfaces()

	if ifaces == nil || len(ipList) == 0 {
		return
	}

	for _, iface := range *ifaces {
		for _, ip := range ipList {
			tmp := &TCPTarget{
				SrcIP:    iface.IP,
				SrcPort:  layers.TCPPort(ports.DEFAULT_SOURCEPORT),
				DstIP:    ip,
				DstPorts: ports.GetDefaultPorts(),
				Handle:   iface.Handle,
				SrcMac:   iface.HWAddr,
				DstMac:   *arpInstance.AMap[common.IP2Uint32(iface.Gateway)],
			}
			t.TargetCh <- tmp
			fmt.Println(tmp)
		}
	}
}

func (t *TCPScanner) Scan() {
	defer close(t.Stop)
	for target := range t.TargetCh {
		t.SendTCP(target)
	}
}

func (t *TCPScanner) GeneratePorts() []layers.TCPPort {
	return []layers.TCPPort{
		layers.TCPPort(ports.DEFAULT_WEB),
		layers.TCPPort(ports.DEFAULT_WEB_HTTPS),
	}
}

func (t *TCPScanner) SendTCP(target *TCPTarget) {

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

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	for _, port := range target.DstPorts {
		// tcp层
		tcpLayer := &layers.TCP{
			SrcPort: target.SrcPort,
			DstPort: port,
			Seq:     100,
			SYN:     true,
			Options: []layers.TCPOption{},
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
			log.Fatal(err)
		}

		err = target.Handle.WritePacketData(buffer.Bytes())

		if err != nil {
			log.Fatal(err)
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
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		return nil
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	if tcp == nil {
		return nil
	}

	if tcp.DstPort == layers.TCPPort(ports.DEFAULT_SOURCEPORT) {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return nil
		}

		ip, _ := ipLayer.(*layers.IPv4)
		if ip == nil {
			return nil
		}

		fmt.Printf("Receive From %s's Port %d\n", ip.SrcIP, tcp.SrcPort)

		uint32IP := common.IP2Uint32(ip.SrcIP)
		if t.Results[uint32IP] == nil {
			t.Results[uint32IP] = make(map[uint16]bool)
		}

		t.Results[uint32IP][uint16(tcp.SrcPort)] = true

		tmp := TCPResult{
			IP: ip.SrcIP,
			Ports: map[uint16]bool{
				uint16(tcp.SrcPort): true,
			},
		}

		return tmp
	}

	return nil

}

func (t *TCPScanner) CheckIPList(ipList []net.IP) {
	<-t.Stop
	scanports := ports.GetDefaultPorts()
	for _, ip := range ipList {
		uint32IP := common.IP2Uint32(ip)
		if t.Results[uint32IP] == nil {
			t.Results[uint32IP] = make(map[uint16]bool)
			for _, port := range scanports {
				t.Results[uint32IP][uint16(port)] = false
			}
		} else {
			for _, port := range scanports {
				if !t.Results[uint32IP][uint16(port)] {
					t.Results[uint32IP][uint16(port)] = false
				}
			}
		}

	}
}
