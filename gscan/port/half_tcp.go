package port

import (
	"gscan/common"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cmap "github.com/orcaman/concurrent-map/v2"
	"go.uber.org/zap"
)

type HalfTCPScanner struct {
	TargetCh  chan *TCPTarget
	ResultCh  chan *TCPResult
	Timeout   time.Duration
	SrcPost   layers.TCPPort
	OpenPorts cmap.ConcurrentMap[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, bool]]
	Opts      gopacket.SerializeOptions
}

func (t *HalfTCPScanner) Unpack(packet gopacket.Packet) (*layers.TCP, *layers.IPv4, *layers.Ethernet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil, nil
	}
	eth := ethLayer.(*layers.Ethernet)
	if eth == nil {
		return nil, nil, nil
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil, nil
	}
	ip := ipLayer.(*layers.IPv4)
	if ip == nil {
		return nil, nil, nil
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil, nil
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp == nil || tcp.DstPort != t.SrcPost {
		return nil, nil, nil
	}
	return tcp, ip, eth
}

func (t *HalfTCPScanner) Save(sip []byte, sport layers.TCPPort) {
	srcIP, _ := netip.AddrFromSlice(sip)
	if _, ok := t.OpenPorts.Get(srcIP); !ok {
		portSet := cmap.NewWithCustomShardingFunction[layers.TCPPort, bool](func(key layers.TCPPort) uint32 { return uint32(key) })
		t.OpenPorts.Set(srcIP, portSet)
	}
	if res, ok := t.OpenPorts.Get(srcIP); ok {
		res.Set(sport, true)
		logger.Sugar().Debugf("IP: %s, Port: %s, Status: true", sip, sport)
	}
}

func (t *HalfTCPScanner) RecvTCP(packet gopacket.Packet) interface{} {
	if tcp, ip, _ := t.Unpack(packet); tcp != nil {
		t.Save(ip.SrcIP, tcp.SrcPort)
		return TCPResult{
			IP:   ip.SrcIP,
			Port: tcp.SrcPort,
		}
	}
	return nil
}

func (t *HalfTCPScanner) Recv() {
	defer close(t.ResultCh)
	for r := range receiver.Register(TCP_REGISTER_NAME, t.RecvTCP) {
		if result, ok := r.(*TCPResult); ok {
			t.ResultCh <- result
		}
	}
}

func (t *HalfTCPScanner) SendSYNACK(target *TCPTarget) {
	buffer := gopacket.NewSerializeBuffer()
	ethLayer := &layers.Ethernet{
		SrcMAC:       target.SrcMac,
		DstMAC:       target.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    target.SrcIP,
		DstIP:    target.DstIP,
		Flags:    layers.IPv4DontFragment,
	}
	tcpLayer := &layers.TCP{
		SrcPort: target.SrcPort,
		DstPort: target.DstPort,
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
	if err := gopacket.SerializeLayers(buffer, t.Opts, ethLayer, ipLayer, tcpLayer); err != nil {
		logger.Error("SerializeLayers Failed", zap.Error(err))
	}
	if err := target.Handle.WritePacketData(buffer.Bytes()); err != nil {
		logger.Error("WritePacketData Failed", zap.Error(err))
	}
}

func (t *HalfTCPScanner) Scan() {
	for target := range t.TargetCh {
		t.SendSYNACK(target)
	}
}

func (a *HalfTCPScanner) Close() {
	receiver.Unregister(TCP_REGISTER_NAME)
	close(a.TargetCh)
	close(a.ResultCh)
}

func newHalfTCPScanner() *HalfTCPScanner {
	t := &HalfTCPScanner{
		TargetCh:  make(chan *TCPTarget, 10),
		ResultCh:  make(chan *TCPResult, 10),
		OpenPorts: cmap.NewWithCustomShardingFunction[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, bool]](common.Fnv32),
		Opts:      gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
	}
	go t.Recv()
	go t.Scan()
	return t
}
