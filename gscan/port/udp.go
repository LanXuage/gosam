package port

import (
	"gscan/common"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type UDPScanner struct {
	Stop     chan struct{}
	Results  []UDPResult
	ResultCh chan *UDPResult
}

type UDPTarget struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  layers.UDPPort
	DstPorts []layers.UDPPort
	Handle   *pcap.Handle
}

type UDPResult struct {
	IP    net.IP
	Ports map[uint16]bool
}

func InitialUDPScanner() *UDPScanner {
	return &UDPScanner{
		Stop:     make(chan struct{}),
		Results:  []UDPResult{},
		ResultCh: make(chan *UDPResult, 10),
	}
}

func (u *UDPScanner) SendUDP(target UDPTarget) {
	udpBuffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for _, port := range target.DstPorts {
		udpLayer := &layers.UDP{
			SrcPort: target.SrcPort,
			DstPort: port,
		}

		err := gopacket.SerializeLayers(udpBuffer, opts, udpLayer)

		if err != nil {
			log.Fatal(err)
		}

		err = target.Handle.WritePacketData(udpBuffer.Bytes())
		if err != nil {
			log.Fatal(err)
		}
	}

}

func (u *UDPScanner) Recv() {
	defer close(u.ResultCh)
	for r := range common.GetReceiver().Register("udp", u.RecvUDP) {
		if result, ok := r.(*UDPResult); ok {
			u.ResultCh <- result
		}
	}
}

func (u *UDPScanner) RecvUDP(packet gopacket.Packet) interface{} {
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if udpLayer == nil {
		return nil
	}

	udp, _ := udpLayer.(*layers.UDP)
	if udp == nil {
		return nil
	}

	return nil
}
