package port

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type TCPInfo struct {
	SrcIP   net.IP
	SrcPort layers.TCPPort
	DstIP   net.IP
	DstPort layers.TCPPort
	Handle  *pcap.Handle
}

func TCP() {

	handle, err := pcap.OpenLive("en0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	t := &TCPInfo{
		SrcIP:   net.ParseIP("192.168.0.45"),
		SrcPort: 12345,
		DstIP:   net.ParseIP("192.168.0.44"),
		DstPort: 80,
		Handle:  handle,
	}

	fmt.Println(t)

}

func SendTCP(tcpInfo TCPInfo) {
	// tcp层
	tcpLayer := &layers.TCP{
		SrcPort: tcpInfo.SrcPort,
		DstPort: tcpInfo.DstPort,
		Seq:     100,
		SYN:     true,
		Window:  14600,
	}

	// ip层
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    tcpInfo.SrcIP,
		DstIP:    tcpInfo.DstIP,
		Flags:    layers.IPv4DontFragment,
	}

	// 以太层
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

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

}

func Recv() {

}
